module System.PTrace
(PTraceHandle
,PTrace
,runPTrace
,PTRegs(..)
,continue
,StopReason(..)
,PTracePtr(..)
,forkPT
,execPT
,detachPT
,getRegsPT
,setRegsPT
,getDataPT
,setDataPT
,pTracePlusPtr
) where

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
import Foreign.C.Error
import Control.Concurrent
import Data.IORef
import Data.Bits

debug = liftIO . putStrLn

data PTraceHandle = PTH { pthPID :: ProcessID
                         ,pthMem :: Handle
                         ,pthSys :: IORef SysState}

data SysState = Entry | Exit deriving Show

{-
  We create the PTrace monad. Technically, this could be almost as powerful
  as the IO monad, as it allows for execution of arbitrary code. However, it
  only allows for this execution in a specific other thread, and so does still
  provide useful sandboxing effects. It also implicitly has a Reader monad,
  which holds the handle to the thread being traced.

  Similar to the ST monad though, on some level it is really just the IO monad.
  Nothing fancy is actually going on with its declaration.
-}
newtype PTrace a = PT { ptraceInner :: ReaderT PTraceHandle IO a }
   deriving (Functor, Monad, MonadIO)

getHandle :: PTrace PTraceHandle
getHandle = PT $ ask

errNeg :: String -> PTrace Int -> PTrace ()
errNeg msg m = do
  e <- m
  if (e < 0)
    then liftIO $ throwErrno msg
    else return ()

ptrace :: Request -> PTracePtr a -> Ptr b -> PTrace Int
ptrace req pA pB = do
  pth <- getHandle
  n <- liftIO $ ptraceRaw (toCReq req) (pthPID pth) (unpackPtr pA) (ptrToWordPtr pB)
  return $ fromIntegral n

runPTrace :: PTraceHandle -> PTrace a -> IO a
runPTrace h m = runReaderT (ptraceInner m) h

forkPT :: IO () -> IO PTraceHandle
forkPT m = do
  pid <- forkProcess $ traceMe >> m
  status <- getProcessStatus True True pid
  case status of
    Just (Stopped _) -> do mem <- openBinaryFile ("/proc" </> (show pid) </> "mem")
                                                 ReadWriteMode
                           setOptions pid
                           e <- newIORef Entry
                           return $ PTH {pthPID = pid, pthMem = mem,
                                         pthSys = e}
    _                -> error "Failed to get a stopped process."
    where setOptions :: CPid -> IO ()
          setOptions pid = void $ ptraceRaw (toCReq SetOptions) pid 0 1 -- PTRACE_O_SYSGOOD

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

liftPTWrap :: ((a -> IO b) -> IO c) -> (a -> PTrace b) -> PTrace c
liftPTWrap m f = do
  h <- getHandle
  liftIO $ m $ \x -> (runPTrace h $ f x)

ptAlloca :: (Storable a) => ((Ptr a) -> PTrace b) -> PTrace b
ptAlloca = liftPTWrap alloca

peekPT p = liftIO $ peek p
pokePT p k = liftIO $ poke p k

getRegsPT :: PTrace PTRegs
getRegsPT = ptAlloca $ \p -> do
  errNeg "getRegsPT" $ ptrace GetRegs traceNull p
  peekPT p

setRegsPT :: PTRegs -> PTrace ()
setRegsPT r = ptAlloca $ \p -> do
  pokePT p r
  errNeg "setRegsPT" $ ptrace SetRegs traceNull p

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
                debug $ "Read state, got " ++ (show e)
                case e of 
                  Entry -> do liftIO $ writeIORef r Exit
                              return SyscallEntry
                  Exit  -> do liftIO $ writeIORef r Entry
                              return SyscallExit
        else continue
      | otherwise -> do liftIO $ print x
                        continue
    Just (Exited c) -> return $ ProgExit c
    _ -> continue -- TODO handle other events other than syscall

getDataPT :: Ptr a -> PTracePtr a -> Int -> PTrace Int
getDataPT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr source
  liftIO $ hGetBufNonBlocking mem target len

setDataPT :: PTracePtr a -> Ptr a -> Int -> PTrace Int
setDataPT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr target
  liftIO $ hPutBufNonBlocking mem source len
  -- TODO investigate whether hPutBufNonBlocking does what I think
