-- | Moderately safe bindings to the Linux ptrace facility
--   Provides the ability to get and set both registers
--   and data, and has a separate pointer type for remote data
--   to help keep things straight.
module System.PTrace
(
-- * Starting a trace
PTraceHandle
,forkPT
,execPT
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

debug _ = return () --liftIO . putStrLn

data PTraceHandle = PTH { pthPID :: ProcessID
                         ,pthMem :: Handle
                         ,pthSys :: IORef SysState}

data SysState = Entry | Exit deriving Show

data PTError = ReadError
             | WriteError
             | UnknownError String deriving Show

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

runPTrace :: PTraceHandle -> PTrace a -> IO (Either PTError a)
runPTrace h m = runReaderT (runErrorT (ptraceInner m)) h

forkPT :: IO () -> IO PTraceHandle
forkPT m = do
  pid <- forkProcess $ traceMe >> m
  status <- getProcessStatus True True pid
  case status of
    Just (Stopped _) -> do mem <- openBinaryFile ("/proc" </>
                                                  show pid </>
                                                  "mem")
                                                 ReadWriteMode
                           hSetBuffering mem NoBuffering
                           setOptions pid
                           e <- newIORef Entry
                           return PTH {pthPID = pid, pthMem = mem,
                                       pthSys = e}
    _                -> error "Failed to get a stopped process."
    where setOptions :: CPid -> IO ()
          setOptions pid = void $ ptraceRaw (toCReq SetOptions) pid 0 1
                                                    -- PTRACE_O_SYSGOOD

execPT :: FilePath                 -- ^ File to run
       -> Bool                     -- ^ Search Path?
       -> [String]                 -- ^ Arguments
       -> Maybe [(String, String)] -- ^ Environment
       -> IO PTraceHandle          -- ^ Traced Process Handle
execPT f s a e = forkPT (executeFile f s a e)

attachPT :: ProcessID
         -> IO PTraceHandle
attachPT = undefined

detachPT :: PTrace ()
detachPT = undefined

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

getRegsPT :: PTrace PTRegs
getRegsPT = ptAlloca $ \p -> do
  errNeg (UnknownError "getRegsPT") $ ptrace GetRegs traceNull p
  peekPT p

setRegsPT :: PTRegs -> PTrace ()
setRegsPT r = ptAlloca $ \p -> do
  pokePT p r
  errNeg (UnknownError "getRegsPT") $ ptrace SetRegs traceNull p

continue :: PTrace StopReason
continue = do
  debug "Continuing."
  pth <- getHandle
  ptrace Syscall traceNull nullPtr
  status <- liftIO $ getProcessStatus True False $ pthPID pth
  case status of
    Just (Stopped x) | x .&. 63 == sigTRAP -> do
      debug "Found a SIGTRAP"
      if (x .&. 128) == 128 -- sysgood
        then do r <- fmap pthSys getHandle
                debug "Acquired state handle"
                e <- liftIO $ readIORef r
                debug $ "Read state, got " ++ show e
                case e of 
                  Entry -> do liftIO $ writeIORef r Exit
                              return SyscallEntry
                  Exit  -> do liftIO $ writeIORef r Entry
                              return SyscallExit
        else return $ Sig x
      | otherwise -> return $ Sig x
    Just (Exited c) -> return $ ProgExit c
    Just x -> do liftIO $ print ("DANGER!", x)
                 continue
    _ -> continue -- TODO handle other events other than syscall

getDataPT :: Ptr a -> PTracePtr a -> Int -> PTrace Int
getDataPT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr source
  liftIO $ hGetBuf mem target len `catch` (\(_ :: IOError) -> return 0)
setDataPT :: PTracePtr a -> Ptr a -> Int -> PTrace ()
setDataPT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr target
  success <- liftIO $ (do hPutBuf mem source len; return True) `catch`
                      (\(_ :: IOError) -> return False)
  unless success $ throwError WriteError
