module System.PTrace.Raw where

import Foreign.C.Types
import Foreign.Ptr
import System.Posix.Types
import System.PTrace.Types
import Control.Monad
import Foreign.C.Error
import Foreign.Marshal.Alloc
import Data.Bits
import Foreign.Storable
import System.Posix.Process.Internals

foreign import ccall unsafe "ptrace" ptraceRaw :: CInt
                                               -> CPid
                                               -> WordPtr
                                               -> WordPtr
                                               -> IO CLong

traceMe :: IO ()
traceMe = void $ ptraceRaw 0 0 0 0

foreign import ccall unsafe "wait4" waitpidRaw :: CPid
                                              -> Ptr CInt
                                              -> CInt
                                              -> CInt
                                              -> IO CPid

getEv :: CPid -> IO (CPid, CInt, ProcessStatus)
getEv p = alloca $ \status -> do
  pid <- throwErrnoIfMinus1Retry "wait4" $ waitpidRaw p status 0x40000000 0
  stat  <- peek status
  stat' <- decipherWaitStatus stat
  return $ (pid, (stat `shiftR` 16) .&. 0xFFF, stat')
