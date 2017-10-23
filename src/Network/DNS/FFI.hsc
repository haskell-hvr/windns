{-# LANGUAGE CApiFFI #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}

-- |
-- Copyright: © 2017 Herbert Valerio Riedel
-- License: GPLv3
--
module Network.DNS.FFI where

import Data.Bits
import Control.DeepSeq
import Control.Exception
import Control.Monad
import Control.Applicative as App
import Foreign.C.Types
import Foreign.Storable
import Foreign.Ptr
import Foreign.Marshal.Alloc
import Data.Word
import Data.Int
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Numeric                (showHex)

#include <windows.h>
#include <windns.h>

type DWORD = #type DWORD
type BOOL  = #type BOOL

-- DNS_STATUS WINAPI DnsQuery_A(PCSTR,WORD,DWORD,PVOID,PDNS_RECORDA*,PVOID*);

----------------------------------------------------------------------------

-- | Cache time-to-live expressed in seconds
newtype TTL  = TTL Int32 deriving (Eq,Ord,Read,Show,NFData)

-- | @\<character-string\>@ as per [RFC 1035, section 3.3](https://tools.ietf.org/html/rfc1035#section-3.3).
--
-- A sequence of up to 255 octets
--
-- The limit of 255 octets is caused by the encoding which uses by a
-- prefixed octet denoting the length.
newtype CharStr = CharStr ByteString deriving (Eq,Ord,Read,Show,NFData)

-- | @\<domain-name\>@ as per [RFC 1035, section 3.3](https://tools.ietf.org/html/rfc1035#section-3.3).
--
-- A domain-name represented as a series of labels separated by dots.
newtype Name    = Name ByteString deriving (Eq,Ord,Read,Show,NFData)


-- | An IPv6 address
--
-- The IP address is represented in network order,
-- i.e. @2606:2800:220:1:248:1893:25c8:1946@ is
-- represented as @(IPv6 0x2606280002200001 0x248189325c81946)@.
data IPv6 = IPv6 !Word64 !Word64
          deriving (Eq,Ord,Read)

instance Show IPv6 where
    showsPrec p (IPv6 hi lo) = showParen (p >= 11) (showString "IPv6 0x" . showHex hi . showString " 0x" . showHex lo)

mkIPv6 :: Word32 -> Word32 -> Word32 -> Word32 -> IPv6
mkIPv6 a b c d = IPv6 ((fromIntegral a `shiftL` 32) .|. fromIntegral b)
                      ((fromIntegral c `shiftL` 32) .|. fromIntegral d)

-- | An IPv4 address
--
-- The IP address is represented in network order, i.e. @127.0.0.1@ is
-- represented as @(IPv4 0x7f000001)@.
data IPv4 = IPv4 !Word32
          deriving (Eq,Ord,Read)

instance Show IPv4 where
    showsPrec p (IPv4 n) = showParen (p >= 11) (showString "IPv4 0x" . showHex n)

----------------------------------------------------------------------------

dnsQuery :: Bool -> Name -> DnsType -> IO (Either Int [DnsRecord])
dnsQuery exact (Name n) ty = do
  alloca $ \pst -> do
    BS.useAsCString n $ \n' ->
      bracket (c_dns_query n' (fromDnsType ty) pst)
              (c_free_record)
              $ \p0 -> do
                st <- peek pst
                if (st /= 0)
                  then pure (Left (fromIntegral st))
                  else do
                    tmp <- travRecs (peekRec n') p0
                    if exact
                      then pure (Right [ r | (b,r) <- tmp, b ])
                      else pure (Right (map snd tmp))


foreign import capi safe "hs_windns.h hs_dns_query" c_dns_query :: Ptr CChar -> DWORD -> Ptr CLong -> IO (Ptr DnsRecord)

foreign import capi unsafe "hs_windns.h hs_free_record" c_free_record :: Ptr DnsRecord -> IO (Ptr DnsRecord)

foreign import capi unsafe "hs_windns.h DnsNameCompare_A" c_dns_name_eq :: Ptr CChar -> Ptr CChar -> IO BOOL


travRecs :: (Ptr DnsRecord -> IO a) -> Ptr DnsRecord -> IO [a]
travRecs f p0 = go [] p0
  where
    go acc p
      | p == nullPtr = App.pure (reverse acc)
      | otherwise    = do
          x <- f p
          p' <- next p
          go (x:acc) p'

    next :: Ptr DnsRecord -> IO (Ptr DnsRecord)
    next = #{peek DNS_RECORDA, pNext}


peekRec :: Ptr CChar -> Ptr DnsRecord -> IO (Bool,DnsRecord)
peekRec n0 p = do
  drNamePtr <- #{peek DNS_RECORDA, pName} p
  same <- c_dns_name_eq n0 drNamePtr
  drName <- Name <$> BS.packCString drNamePtr
  drType <- toDnsType <$> #{peek DNS_RECORDA, wType} p
  drTTL  <- TTL . fromIntegral <$> (#{peek DNS_RECORDA, dwTtl} p :: IO DWORD)

  drData <- case drType of
              DnsTypeA    -> DnsDataA . IPv4 <$> #{peek DNS_RECORDA, Data.A.IpAddress} p
              DnsTypeAAAA -> DnsDataAAAA <$> (mkIPv6 <$> #{peek DNS_RECORDA, Data.AAAA.Ip6Address.IP6Dword[0]} p
                                                     <*> #{peek DNS_RECORDA, Data.AAAA.Ip6Address.IP6Dword[1]} p
                                                     <*> #{peek DNS_RECORDA, Data.AAAA.Ip6Address.IP6Dword[2]} p
                                                     <*> #{peek DNS_RECORDA, Data.AAAA.Ip6Address.IP6Dword[3]} p)
              DnsTypeTXT  -> do
                cnt <- #{peek DNS_RECORDA, Data.TXT.dwStringCount} p
                let ptr0 = #{ptr DNS_RECORDA, Data.TXT.pStringArray[0]} p
                tptrs <- forM [0.. fromIntegral (cnt :: DWORD)] (peekElemOff ptr0)
                DnsDataTXT <$> mapM (fmap CharStr . BS.packCString) tptrs

  evaluate $ force (same /= 0,DnsRecord{..})

data DnsRecord = DnsRecord
    { drName :: !Name
    , drType :: !DnsType
    , drTTL  :: !TTL
    , drData :: !DnsData
    }

instance NFData DnsRecord where
  rnf (DnsRecord n y t d) = n `deepseq` y `deepseq` t `deepseq` d `deepseq` ()


data DnsData = DnsDataA    !IPv4
             | DnsDataAAAA !IPv6
             | DnsDataTXT  [CharStr]
             | DnsData     !DWORD -- unknown/unsupported
             deriving Show

instance NFData DnsData where
  rnf (DnsDataA _) = ()
  rnf (DnsDataAAAA {}) = ()
  rnf (DnsDataTXT ts) = rnf ts
  rnf (DnsData _) = ()

dnsDataType :: DnsData -> DnsType
dnsDataType DnsDataA {}    = DnsTypeA
dnsDataType DnsDataAAAA {} = DnsTypeAAAA
dnsDataType DnsDataTXT {}  = DnsTypeTXT
dnsDataType (DnsData w)    = DnsType w

data DnsType = DnsTypeA
             | DnsTypeAAAA
             | DnsTypeTXT
             | DnsType !DWORD
             deriving (Show)

instance NFData DnsType where rnf t = seq t ()

eqType :: DnsType -> DnsType -> Bool
eqType x y = fromDnsType x == fromDnsType y

fromDnsType :: DnsType -> DWORD
fromDnsType x = case x of
  DnsTypeA    -> #const DNS_TYPE_A
  DnsTypeAAAA -> #const DNS_TYPE_AAAA
  DnsTypeTXT  -> #const DNS_TYPE_TEXT
  DnsType w   -> w

toDnsType :: DWORD -> DnsType
toDnsType w = case w of
  #{const DNS_TYPE_A   } -> DnsTypeA
  #{const DNS_TYPE_AAAA} -> DnsTypeAAAA
  #{const DNS_TYPE_TEXT} -> DnsTypeTXT
  _                      -> DnsType w
