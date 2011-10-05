module System.PTrace.PTRegs where

import Data.Word
import Foreign.Storable
import Foreign.CStorable
import GHC.Generics

-- PENDING CStorable merging into Storable, simplify this
data PTRegs =
  PTRegs {ebx, ecx, edx, esi, edi, ebp, eax, xds, xes, xfs, xgs, orig_eax,
          eip, xcs, eflags, esp, xss :: Word64} deriving (Generic, Show)

instance CStorable PTRegs

--TODO fix CStorable package to compute alignment better...
instance Storable PTRegs where
  peek        = cPeek
  poke        = cPoke
  sizeOf      = cSizeOf
  alignment _ = 256
