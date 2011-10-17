module System.PTrace.Types where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import System.Posix.Signals
import System.PTrace.PTRegs
import System.Exit
import System.Posix.Types
import System.IO
import Data.IORef
import System.PTrace.PTRegs

-- | Simple wrapper newtype around a pointer to make it a tracing
--   pointer. Note that the storable instance will only work if the
--   target architecture is the same as the tracing architecture
newtype PTracePtr a = PTP (Ptr a) deriving (Show, Storable, Eq)

--TODO make a ptraceptr reflect the target

-- | Advances the pointer in the same manner as 'plusPtr' would. May not
--   operate as expected if the traced architecture does not match the
--   one doing the tracing
pTracePlusPtr :: PTracePtr a -> Int -> PTracePtr a
pTracePlusPtr (PTP fp) n = PTP $ fp `plusPtr` n

-- | A null pointer to anything (essentially the equivalent of the C NULL
traceNull :: PTracePtr a
traceNull = PTP nullPtr

unpackPtr :: PTracePtr a -> WordPtr
unpackPtr (PTP ptr) = ptrToWordPtr ptr

-- | Abstract type representing a handle to a trace in progress
--   Using 'detachPT' or 'killPT' invalidates the 'PTraceHandle', similar
--   to what happens if you 'close' a 'Handle'. It is also invalidated
--   on any outside action that terminates the traced process.
--   Note: While you may think you can cleverly serialize this to another
--   thread, you cannot. The system pins the permissions to an individual
--   thread, so migrating the handle will not allow another thread to
--   trace properly.
data PTraceHandle = PTH { pthPID :: ProcessID
                         ,pthMem :: Handle
                         ,pthSys :: IORef SysState}

data SysState = Entry | Exit deriving Show

-- | Indicates why the trace has returned control to you
data StopReason = SyscallEntry        -- ^ Process is about to syscall
                | SyscallExit         -- ^ Process has just syscalled
                | ProgExit ExitCode   -- ^ Exited with specified code
                | Sig Signal          -- ^ Received specified signal
                | Forked ProcessID    -- ^ Process forked, new pid
                | Cloned ProcessID    -- ^ Process cloned, new pid
                deriving Show

data Request =
     TraceMe
   | PeekText
   | PeekData
   | PeekUser
   | PokeText
   | PokeData
   | PokeUser
   | Continue
   | Kill
   | SingleStep
   | GetRegs
   | SetRegs
   | GetFPRegs
   | SetFPRegs
   | Attach
   | Detach
   | GetFPXRegs
   | SetFPXRegs
   | Syscall
   | SysEmu
   | SysEmuSingle
   | SetOptions
   | GetEventMsg
   | GetSigInfo
   | SetSigInfo

toCReq :: Request -> CInt
toCReq TraceMe      = 0
toCReq PeekText     = 1
toCReq PeekData     = 2
toCReq PeekUser     = 3
toCReq PokeText     = 4
toCReq PokeData     = 5
toCReq PokeUser     = 6
toCReq Continue     = 7
toCReq Kill         = 8
toCReq SingleStep   = 9
toCReq GetRegs      = 12
toCReq SetRegs      = 13
toCReq GetFPRegs    = 14
toCReq SetFPRegs    = 15
toCReq Attach       = 16
toCReq Detach       = 17
toCReq GetFPXRegs   = 18
toCReq SetFPXRegs   = 19
toCReq Syscall      = 24
toCReq SysEmu       = 31
toCReq SysEmuSingle = 32
toCReq SetOptions   = 0x4200
toCReq GetEventMsg  = 0x4201
toCReq GetSigInfo   = 0x4202
toCReq SetSigInfo   = 0x4203
