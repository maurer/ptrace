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

foreign import ccall unsafe "ptrace" ptraceRaw :: CInt -> CPid -> WordPtr -> WordPtr -> IO CLong

traceMe :: IO ()
traceMe = void $ ptraceRaw 0 0 0 0

foreign import ccall safe "waitpid" waitpidRaw :: CPid -> Ptr CInt -> CInt -> IO CPid

getSysGood :: CPid -> IO Bool
getSysGood pid  = alloca $ \status -> do
  throwErrnoIfMinus1 "waitpid" $ waitpidRaw pid status 0
  stat <- peek status
  return $ (0x80 .&. stat) /= 0
