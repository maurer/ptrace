module System.PTrace.X86_64 where

import Data.Word
import Foreign.Storable
import Foreign.CStorable
import GHC.Generics


-- PENDING CStorable merging into Storable, simplify this
data PTRegs =
  PTRegs {r15,r14,r13,r12,rbp,rbx,r11,r10,r9,r8,rax,rcx,rdx,rsi,
          rdi,orig_rax,rip,cs,eflags,rsp,ss,fs_base,gs_base,ds,es,
          fs,gs :: Word64} deriving Generic

instance CStorable PTRegs

instance Storable PTRegs where
  peek      = cPeek
  poke      = cPoke
  sizeOf    = cSizeOf
  alignment _ = 256
