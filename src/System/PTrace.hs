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
,getMemMap
,MemRegion(..)
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
import Foreign.Marshal.Utils
import Control.Applicative

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
             | NoTranslation       -- ^ Pointer does not exist in memmap
             | NoMapping
             | UnknownError String -- ^ Other error
               deriving Show

instance Error PTError where
  strMsg = UnknownError

getPPid pth = P $ pthPID pth

getMemMap :: PTrace (Map.Map WordPtr MemRegion)
getMemMap = do
  pth <- getHandle
  fmap (Map.map (\m -> m {mrLocal = Nothing})) $ liftIO $ readMVar $ pthMemMap pth

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
  } deriving (Functor, Monad, MonadIO, Applicative)

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
                            (_:(_:_:x:_):_) = words l
                            [start, end] = map (\x -> fromIntegral $ read ("0x" ++ x)) [hexA, tail hexB]
                        in MR {mrStart = start, mrEnd = end, mrLocal = Nothing, mrExec = x == 'x'}

updateMemMap :: Map.Map WordPtr MemRegion -> FilePath -> Fd -> PTrace (Map.Map WordPtr MemRegion)
updateMemMap origMap maps mem = do
  -- Load new mapping
  newMapDesc <- liftIO $ loadMap maps
  -- Purge pass: Unmap and remove all entries not present in the current mapping
  let (purgedMap, toPurge) = Map.partition (present newMapDesc) origMap
  liftIO $ mapM_ purge $ Map.elems toPurge
  -- Load pass: Map and add all entries present in the current mapping, but not our core
  newMaps <- T.traverse (mapRegion mem) $ Map.filter (not . (present purgedMap)) newMapDesc
  return $ Map.union purgedMap newMaps
  where present :: Map.Map WordPtr MemRegion -> MemRegion -> Bool
        present base target = case Map.lookup (mrStart target) base of
                                Just v  -> (mrEnd v) == (mrEnd target)
                                Nothing -> False
        purge :: MemRegion -> IO ()
        purge mr = case mrLocal mr of
                     Just local -> throwErrnoIfMinus1_ "purge failed" $ c'munmap local (mrSize mr)
                     Nothing    -> return ()
        mapRegion :: Fd -> MemRegion -> PTrace MemRegion
        mapRegion (Fd fd) mr | (not (mrExec mr)) = do
          --Kick the target upside the head, make sure it's there when we go to grab it
          prepareMap (mrSize mr) (fromIntegral $ mrStart mr)
          --Actually invoke the mapper
          p <- liftIO $ c'mmap nullPtr (mrSize mr) (c'PROT_READ .|. c'PROT_WRITE) c'MAP_PRIVATE fd (fromIntegral $ mrStart mr)
          if p == (intPtrToPtr $ fromIntegral (-1)) --Map failed
            then return $ mr {mrLocal = Nothing}  --Indicate that this region is not in happyland
            else return $ mr {mrLocal = Just p}
                             | otherwise = return $ mr {mrLocal = Nothing} --Don't touch exec
        mrSize mr = ((fromIntegral $ mrEnd mr) - (fromIntegral $ mrStart mr))
        prepareMap size ptr | size <= 0 = return ()
                            | otherwise = do ptrace PeekData (PTP $ wordPtrToPtr $ fromIntegral ptr) nullPtr
                                             prepareMap (size - 4096) (ptr + 4096) --TODO demagic page size
                                             
makeHandle :: CPid -> IO PTraceHandle
makeHandle pid = do
  let procDir = "/proc" </> show pid
  let memPath = procDir </> "mem"
  mem   <- openBinaryFile memPath ReadWriteMode
  memFd <- openFd memPath ReadWrite Nothing defaultFileFlags
  let maps = procDir </> "maps"
  Right memMap <- runPTrace (PTH {pthPID = pid}) $ updateMemMap Map.empty maps memFd
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
  memMap' <- updateMemMap memMap (pthMaps pth) (pthMemFd pth)
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
slowWrite _ _ 0 = return () -- 0
slowWrite target source len | len < 8 = do
  z <- liftIO $peek (castPtr source)
  v <- ptrace PeekData target nullPtr
  ptrace PokeData target $ wordPtrToPtr $ fromIntegral $ (((v `shiftR` 8) `shiftL` 8) .|. (fromIntegral (z :: Word8)))
  r <- slowWrite (target `pTracePlusPtr` 1) (source `plusPtr` 1) (len - 1)
  return () -- (r + 1)
                            | len >= 8 = do
  z <- liftIO $ peek (castPtr source)
  v <- ptrace PokeData target z
  r <- slowWrite (target `pTracePlusPtr` 8) (source `plusPtr` 8) (len - 8)
  return () --(r + 8)

translatePtr :: PTracePtr a -> PTrace (Ptr a)
translatePtr pptr = (translatePtr' pptr) `catchError` (\e -> case e of NoMapping -> throwError e; NoTranslation -> do refreshMemMap; translatePtr' pptr)
--TODO WARNING! THREAD SAFETY! Pointer could become invalid.
  --TODO to make this faster, switch the core image data structure
  where translatePtr' ptr = do
          let wp = unpackPtr pptr
          mMemMap <- fmap pthMemMap getHandle
          memMap  <- liftIO $ readMVar mMemMap
          case filter (<= wp) (Map.keys memMap) of
            [] -> throwError NoTranslation
            xs -> do let candidate = memMap Map.! (maximum xs)
                     if (mrEnd candidate) < wp
                        then throwError NoTranslation
                        else case mrLocal candidate of
                               Nothing -> throwError NoMapping
                               Just x  -> return $ castPtr x

multipath :: MonadError e m => e -> [m a] -> m a
multipath e [] = throwError e
multipath e (x : xs) = catchError x (\_ -> multipath e xs)

(<#>) :: [a -> b] -> a -> [b]
fs <#> x = map (\f -> f x) fs

-- | Attempts to read up to the specified length from the source into the
--   destination.
--   It will still succeed on non-erroring partial reads, and will return
--   the number of bytes read.
getDataPT :: Ptr a       -- ^ Destination buffer
          -> PTracePtr a -- ^ Source buffer
          -> Int         -- ^ Max Length
          -> PTrace Int  -- ^ Length Read
getDataPT _ _ 0 = return 0
getDataPT target source len = do
  --TODO add validation and support for region-spanning reads
  multipath ReadError $ [getFilePT] <#> target <#> source <#> len

getMappedPT :: Ptr a       -- ^ Destination buffer
            -> PTracePtr a -- ^ Source buffer
            -> Int         -- ^ Max Length
            -> PTrace Int  -- ^ Length Read
getMappedPT target source len = do
  source' <- translatePtr source
  liftIO $ copyBytes target source' len
  return len

getFilePT :: Ptr a       -- ^ Destination buffer
          -> PTracePtr a -- ^ Source buffer
          -> Int         -- ^ Max Length
          -> PTrace Int  -- ^ Length Read
getFilePT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr source
  v <- liftIO $ fmap Right (hGetBuf mem target len) `catch`
                (\(_ :: IOError) -> return $ Left ReadError)
  case v of
    Left e  -> do liftIO $ putStrLn "Warning! getFilePT failed..."
                  throwError e
    Right x -> return x

-- | Attempts to write the specified length into the target from the source.
setDataPT :: PTracePtr a -- ^ Destination buffer
          -> Ptr a       -- ^ Source buffer
          -> Int         -- ^ Length
          -> PTrace ()
setDataPT _ _ 0 = return ()
setDataPT  target source len = do
  liftIO $ putStrLn "setData invoked"
  multipath WriteError $ [setFilePT] <#> target <#> source <#> len

setMappedPT :: PTracePtr a -- ^ Destination buffer
            -> Ptr a       -- ^ Source buffer
            -> Int         -- ^ Max Length
            -> PTrace ()
setMappedPT target source len = do
  liftIO $ putStrLn "setData invoked"
  --TODO add validation and support for region-spanning writes
  target' <- translatePtr target
  liftIO $ copyBytes target' source len
  return ()

setFilePT :: PTracePtr a -- ^ Destination buffer
          -> Ptr a       -- ^ Source buffer
          -> Int         -- ^ Max Length
          -> PTrace ()
setFilePT target source len = do
  mem <- fmap pthMem getHandle
  liftIO $ hSeek mem AbsoluteSeek $ fromIntegral $ unpackPtr target
  v <- liftIO $ fmap Right (hPutBuf mem source len) `catch`
                (\(_ :: IOError) -> return $ Left WriteError)
  case v of
    Left e  -> do liftIO $ putStrLn "Warning! setFilePT failed..."
                  throwError e
    Right x -> return x

