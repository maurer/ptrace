-- | Moderately safe bindings to the Linux ptrace facility
--   Provides the ability to get and set both registers
--   and data, and has a separate pointer type for remote data
--   to help keep things straight.
--   Please note, when using this library, you MUST run in a bound thread.
--   If you do not, you will receive spurious permissions errors.
module System.PTrace
(
-- * Starting a trace
PTraceHandle
,forkPT
,execPT
-- * PTrace Environment
,PTrace
,runPTrace
-- * Stepping a trace
,StopReason(..)
,PTError(..)
,continue
-- * Remote Pointers
,PTracePtr(..)
,pTracePlusPtr
-- * Interacting with the target
,PTRegs(..)
,getRegsPT
,setRegsPT
,getDataPT
,setDataPT
-- * Ending the trace
,detachPT
,killPT
) where

import Prelude hiding (catch)
import Control.Monad.Reader
import System.Posix.Process
import System.Posix.Types
import System.PTrace.Raw
import System.PTrace.Types
import System.Posix.Signals
import Foreign.Ptr
import System.IO
import System.FilePath
import Foreign.Storable
import Foreign.Marshal.Alloc
import Data.IORef
import Data.Bits
import Control.Monad.Error
import Control.Exception
import System.PTrace.PTRegs

--TODO load from header

sysGood = 0x80
traceSysGood = 0x1

debug _ = return () --liftIO . putStrLn

-- | Types of errors occurring inside 'PTrace'
--   Only basic information is available at the moment, more may
--   be added later.
data PTError = ReadError           -- ^ Remote read failed
             | WriteError          -- ^ Remote write failed
             | UnknownError String -- ^ Other error
               deriving Show

instance Error PTError where
  strMsg = UnknownError

{-
  We create the PTrace monad. Technically, this could be almost as powerful
  as the IO monad, as it allows for execution of arbitrary code. However, it
  only allows for this execution in a specific other thread, and so does still
  provide useful sandboxing effects. It also implicitly has a Reader monad,
  which holds the handle to the thread being traced.

  Similar to the ST monad though, on some level it is really just the IO
  monad.
  Nothing fancy is actually going on with its declaration.
-}
-- | This monad encapsulates the resources needed for basic ptrace
--   actions, holding the necessary references to output sensical
--   information in a timely fashion, and wrapping up errors in a pure
--   fashion. It is also an instance of 'MonadIO', should you feel the need
--   to access IO from inside it (ptracing is inherently unsafe, so this
--   should not be too terrifying).
newtype PTrace a = PT {
  ptraceInner :: ErrorT PTError (ReaderT PTraceHandle IO) a
  } deriving (Functor, Monad, MonadIO)

instance MonadError PTError PTrace where
  throwError e = PT $ throwError e
  catchError m f = PT $ catchError (ptraceInner m) (ptraceInner . f)

getHandle :: PTrace PTraceHandle
getHandle = PT ask

errNeg :: PTError -> PTrace Int -> PTrace ()
errNeg msg m = do
  e <- m
  when (e < 0) $ throwError msg

ptrace :: Request -> PTracePtr a -> Ptr b -> PTrace Int
ptrace req pA pB = do
  pth <- getHandle
  liftIO $ fmap fromIntegral $ ptraceRaw (toCReq req)
                                         (pthPID pth)
                                         (unpackPtr pA)
                                         (ptrToWordPtr pB)

-- | Given a 'PTraceHandle' (as created by 'forkPT' or 'execPT'),
--   allows you to perform a PTrace action on it.
runPTrace :: PTraceHandle -> PTrace a -> IO (Either PTError a)
runPTrace h m = runReaderT (runErrorT (ptraceInner m)) h

-- | Given an IO action, spawns it in a new thread, stops it, and gives
--   you back a handle to trace it with.
forkPT :: IO ()           -- ^ The action to trace
       -> IO PTraceHandle -- ^ A handle to the paused action
forkPT m = do
  pid <- forkProcess $ traceMe >> m
  status <- getProcessStatus True True pid
  case status of
    Just (Stopped _) -> makeHandle pid
    _                -> error "Failed to get a stopped process."

makeHandle :: CPid -> IO PTraceHandle
makeHandle pid = do
  mem <- openBinaryFile ("/proc" </> show pid </> "mem") ReadWriteMode
  hSetBuffering mem NoBuffering
  setOptions pid
  e <- newIORef Entry
  return PTH {pthPID = pid, pthMem = mem,
                       pthSys = e}
  where setOptions :: CPid -> IO ()
        setOptions pid = void $ ptraceRaw (toCReq SetOptions)
                                          pid
                                          0
                                          traceSysGood

-- | Takes in a description of a program to execute, then starts it
--   in a tracing context, and gives you back the handle
execPT :: FilePath                 -- ^ File to run
       -> Bool                     -- ^ Search Path?
       -> [String]                 -- ^ Arguments
       -> Maybe [(String, String)] -- ^ Environment
       -> IO PTraceHandle          -- ^ A handle to the paused executable
execPT f s a e = forkPT (executeFile f s a e)

attachPT :: ProcessID
         -> IO PTraceHandle
attachPT = undefined

-- | Releases the handle being traced, allowing the process to do as it
--   wishes.
detachPT :: PTrace ()
detachPT = void $ ptrace Detach traceNull nullPtr

-- | Kills the process being traced.
killPT :: PTrace ()
killPT = void $ ptrace Kill traceNull nullPtr

liftPTWrap :: ((a -> IO (Either PTError c)) -> IO (Either PTError c))
           -> (a -> PTrace c)
           -> PTrace c
liftPTWrap m f = do
  h <- getHandle
  v <- liftIO $ m $ \x -> runPTrace h $ f x
  case v of
    Left e  -> throwError e
    Right x -> return x

ptAlloca :: (Storable a) => (Ptr a -> PTrace b) -> PTrace b
ptAlloca = liftPTWrap alloca

peekPT p = liftIO $ peek p
pokePT p k = liftIO $ poke p k

-- | Acquires the accessible register set from the CPU
getRegsPT :: PTrace PTRegs
getRegsPT = ptAlloca $ \p -> do
  errNeg (UnknownError "getRegsPT") $ ptrace GetRegs traceNull p
  peekPT p

-- | Sets registers, when possible, on to match the specification on the CPU
setRegsPT :: PTRegs -> PTrace ()
setRegsPT r = ptAlloca $ \p -> do
  pokePT p r
  errNeg (UnknownError "getRegsPT") $ ptrace SetRegs traceNull p

-- | Resumes execution of the traced process until it reaches another
--   stopping point, then returns why it stopped.
continue :: PTrace StopReason -- ^ Why it stopped
continue = do
  debug "Continuing."
  pth <- getHandle
  ptrace Syscall traceNull nullPtr
  status <- liftIO $ getProcessStatus True False $ pthPID pth
  case status of
    Just (Stopped x) | x .&. 63 == sigTRAP -> do
      debug "Found a SIGTRAP"
      case x of
        _ | (x .&. sysGood) == sysGood -> do
                r <- fmap pthSys getHandle
                debug "Acquired state handle"
                e <- liftIO $ readIORef r
                debug $ "Read state, got " ++ show e
                case e of 
                  Entry -> do liftIO $ writeIORef r Exit
                              return SyscallEntry
                  Exit  -> do liftIO $ writeIORef r Entry
                              return SyscallExit
          | otherwise -> return $ Sig x
      | otherwise -> return $ Sig x
    Just (Exited c) -> return $ ProgExit c
    Just x -> do liftIO $ print ("DANGER!", x)
                 continue
    _ -> continue -- TODO handle other events other than syscall

-- | Attempts to read up to the specified length from the source into the
--   destination.
--   It will still succeed on non-erroring partial reads, and will return
--   the number of bytes read.
getDataPT :: Ptr a       -- ^ Destination buffer
          -> PTracePtr a -- ^ Source buffer
          -> Int         -- ^ Max Length
          -> PTrace Int  -- ^ Length Read
getDataPT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr source
  v <- liftIO $ fmap Right (hGetBuf mem target len) `catch`
                (\(_ :: IOError) -> return $ Left ReadError)
  case v of
    Left e  -> throwError e
    Right x -> return x

-- | Attempts to write the specified length into the target from the source.
setDataPT :: PTracePtr a -- ^ Destination buffer
          -> Ptr a       -- ^ Source buffer
          -> Int         -- ^ Length
          -> PTrace ()
setDataPT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr target
  success <- liftIO $ (do hPutBuf mem source len; return True) `catch`
                      (\(_ :: IOError) -> return False)
  unless success $ throwError WriteError
