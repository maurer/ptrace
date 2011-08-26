module System.PTrace.Types 
(PTracePtr(..)
,pTracePlusPtr
,traceNull
,unpackPtr
,Request(..)
,toCReq
,PTRegs(..)
,StopReason(..)
) where

import Foreign
import Foreign.Ptr
import Foreign.C.Types
import System.PTrace.X86_64

newtype PTracePtr a = PTP (Ptr a) deriving (Show, Eq)

pTracePlusPtr :: PTracePtr a -> Int -> PTracePtr a
pTracePlusPtr (PTP fp) n = PTP $ fp `plusPtr` n

traceNull :: PTracePtr a
traceNull = PTP nullPtr

unpackPtr :: PTracePtr a -> WordPtr
unpackPtr (PTP ptr) = ptrToWordPtr ptr

data StopReason =
    Exited Int
  | Signal Int
  | Syscalled

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
