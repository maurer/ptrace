-- | Moderately safe bindings to the Linux ptrace facility
--   Provides the ability to get and set both registers
--   and data, and has a separate pointer type for remote data
--   to help keep things straight.
--   Please note, when using this library, you MUST run in a bound thread.
--   If you do not, you will receive spurious permissions errors.
--   Additionally, you may not spawn any children of this thread
--   manually. Doing so 
module System.PTrace
(
-- * Starting a trace
PTraceHandle
,getPPid
,forkPT
,execPT
-- * PTrace Environment
,PTrace
,runPTrace
,makePPid
,PPid(..)
-- * Stepping a trace
,StopReason(..)
,PTError(..)
,advance
,nextEvent
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
import Bindings.MMap
import Data.Maybe
import Control.Concurrent.MVar
import Control.Monad.Reader
import System.Posix.Process
import System.Posix.Types
import System.Posix.IO
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
import Foreign.C.Error
import Data.Word
import qualified Data.Map as Map
import qualified Data.Traversable as T

--TODO load from header

sysGood = 0x80
ptraceEventFork :: Signal
ptraceEventFork = 0x1
ptraceEventVFork :: Signal
ptraceEventVFork = 0x2
ptraceEventClone :: Signal
ptraceEventClone = 0x4
traceSysGood = 0x1
traceFork = 0x2
traceVFork = 0x4
traceClone = 0x8

makePPid = P

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

getPPid pth = P $ pthPID pth

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
  liftIO $ ptrace_pid (pthPID pth) req pA pB

ptrace_pid pid req pA pB =
  fmap fromIntegral $ ptraceRaw (toCReq req)
                                pid
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

buildMap :: [MemRegion] -> Map.Map WordPtr MemRegion
buildMap ms = Map.fromList $ map (\x -> (mrStart x, x)) ms

loadMap :: FilePath -> IO (Map.Map WordPtr MemRegion)
loadMap mapDescr = do
  mapSpec <- fmap ((filter (/= "")) . lines) $ readFile mapDescr
  return $ buildMap $ map parseRegion mapSpec 
  where parseRegion l = let (hexA,  hexB) = break (== '-') $ head $ words l
                            [start, end] = map (\x -> fromIntegral $ read ("0x" ++ x)) [hexA, tail hexB]
                        in MR {mrStart = start, mrEnd = end, mrLocal = Nothing}

updateMemMap :: Map.Map WordPtr MemRegion -> FilePath -> Fd -> IO (Map.Map WordPtr MemRegion)
updateMemMap origMap maps mem = do
  -- Load new mapping
  newMapDesc <- loadMap maps
  -- Purge pass: Unmap and remove all entries not present in the current mapping
  let (purgedMap, toPurge) = Map.partition (present newMapDesc) origMap
  mapM_ purge $ Map.elems toPurge
  -- Load pass: Map and add all entries present in the current mapping, but not our core
  newMaps <- T.traverse (mapRegion mem) $ Map.filter (not . (present purgedMap)) newMapDesc
  return $ Map.union purgedMap newMaps
  where present :: Map.Map WordPtr MemRegion -> MemRegion -> Bool
        present base target = case Map.lookup (mrStart target) base of
                                Just v  -> (mrEnd v) == (mrEnd target)
                                Nothing -> False
        purge :: MemRegion -> IO ()
        purge mr = throwErrnoIfMinus1_ "purge failed" $ c'munmap (fromJust $ mrLocal mr) (mrSize mr)
        mapRegion :: Fd -> MemRegion -> IO MemRegion
        mapRegion (Fd fd) mr = do
          --TODO catch error
          p <- c'mmap nullPtr (mrSize mr) (c'PROT_READ .|. c'PROT_WRITE) c'MAP_SHARED fd (fromIntegral $ mrStart mr)
          return $ mr {mrLocal = Just p}
        mrSize mr = ((fromIntegral $ mrEnd mr) - (fromIntegral $ mrStart mr))

makeHandle :: CPid -> IO PTraceHandle
makeHandle pid = do
  let procDir = "/proc" </> show pid
  let memPath = procDir </> "mem"
  mem   <- openBinaryFile memPath ReadWriteMode
  memFd <- openFd memPath ReadWrite Nothing defaultFileFlags
  let maps = procDir </> "maps"
  memMap <- updateMemMap Map.empty maps memFd
  mMemMap <- newMVar memMap
  hSetBuffering mem NoBuffering
  setOptions pid
  return PTH {pthPID = pid, pthMem = mem, pthMaps = maps, pthMemFd = memFd, pthMemMap = mMemMap}
  where setOptions :: CPid -> IO ()
        setOptions pid = void $ ptraceRaw (toCReq SetOptions)
                                          pid
                                          0
                                          (traceSysGood .|. traceFork .|. traceClone)

refreshMemMap :: PTrace ()
refreshMemMap = do
  pth <- getHandle
  memMap <- liftIO $ takeMVar $ pthMemMap pth
  memMap' <- liftIO $ updateMemMap memMap (pthMaps pth) (pthMemFd pth)
  liftIO $ putMVar (pthMemMap pth) memMap'

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

-- | Advances whatever thread we are in the context of
advance :: PTrace ()
advance = void $ ptrace Syscall (pTracePlusPtr traceNull 1) nullPtr

-- | Matches the next event which occurs on a traced thread
nextEvent :: PPid -> IO (PPid, StopReason) -- ^ Why it stopped
nextEvent (P k) = do
  (pid, ev, status) <- getEv k
  r <- case status of
         (Stopped x) | x .&. 63 == sigTRAP -> do
           debug "Found a SIGTRAP"
           case x of
             _ | (x .&. sysGood) == sysGood -> return SyscallState
               | ((ev .&. ptraceEventFork) == ptraceEventFork)
                 || ((ev .&. ptraceEventClone) == ptraceEventClone) -> do
                     pid' <- alloca $ \pp -> do
                               ptrace_pid pid GetEventMsg traceNull pp
                               liftIO $ peek pp
                     h <- makeHandle pid'
                     return $ Forked h
               | otherwise -> return $ Sig x
           | otherwise -> return $ Sig x
         (Exited c) -> return $ ProgExit c
         x -> error $ "Unhandled status: " ++ (show x)
  return (P pid, r)

slowRead _ _ 0 = return 0
slowRead target source len = do
  v <- ptrace PeekData source nullPtr
  e <- liftIO $ getErrno
  if (v == -1) && (e /= eOK)
    then return 0
    else do liftIO $ poke (castPtr target) v
            r <- slowRead (target `plusPtr` 8) (source `pTracePlusPtr` 8) (len - 8)
            return (r + 8)
slowWrite _ _ 0 = return 0
slowWrite target source len | len < 8 = do
  z <- liftIO $peek (castPtr source)
  v <- ptrace PeekData target nullPtr
  ptrace PokeData target $ wordPtrToPtr $ fromIntegral $ (((v `shiftR` 8) `shiftL` 8) .|. (fromIntegral (z :: Word8)))
  r <- slowWrite (target `pTracePlusPtr` 1) (source `plusPtr` 1) (len - 1)
  return (r + 1)
                            | len >= 8 = do
  z <- liftIO $ peek (castPtr source)
  v <- ptrace PokeData target z
  r <- slowWrite (target `pTracePlusPtr` 8) (source `plusPtr` 8) (len - 8)
  return (r + 8)


-- | Attempts to read up to the specified length from the source into the
--   destination.
--   It will still succeed on non-erroring partial reads, and will return
--   the number of bytes read.
getDataPT :: Ptr a       -- ^ Destination buffer
          -> PTracePtr a -- ^ Source buffer
          -> Int         -- ^ Max Length
          -> PTrace Int  -- ^ Length Read
getDataPT _ _ 0 = return 0
getDataPT  target source len = do
  -- Force the page in
  let src  = unpackPtr source
  let far  = src + 4096
  let stop = far - (far `mod` 4096)
  let len' = min len $ fromIntegral $ stop - src
  r <- catchError (getDataPT' target source len') (\_ -> do liftIO $ print "Early read term"
                                                            slowRead target source len')
  if (r /= len')
     then return r
      else do r' <- getDataPT (target `plusPtr` r) (source `pTracePlusPtr` r) (len - r)
              return $ r + r'
getDataPT' target source len = do
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
setDataPT _ _ 0 = return ()
setDataPT  target source len = do
  -- Force the page in
  let src  = unpackPtr target
  let far  = src + 4096
  let stop = far - (far `mod` 4096)
  let len' = min len $ fromIntegral $ stop - src
  r <- catchError (setDataPT' target source len') (\_ -> do liftIO $ print "Early write term"
                                                            slowWrite target source len')
  if (r /= len')
     then return () --r
      else do r' <- setDataPT (target `pTracePlusPtr` r) (source `plusPtr` r) (len - r)
              return () --  r + r'

setDataPT' target source len = do
  mem <- fmap pthMem getHandle
  v <- liftIO $ (do hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr target
                    fmap Right $ hPutBuf mem source len) `catch`
                         (\(_ :: IOError) -> return $ Left WriteError)
  case v of
    Left e -> throwError e
    Right x -> return len

--TODO arch indep
data PTImage = Map Word64 (Ptr Word8)
