{-# LANGUAGE Trustworthy #-}

-- |
-- Copyright: © 2017 Herbert Valerio Riedel
-- License: GPLv3
--
-- This module implements an API for accessing
-- the [Domain Name Service (DNS)](https://tools.ietf.org/html/rfc1035)
-- resolver service via the standard [<windns.h>/dnsapi.dll](https://msdn.microsoft.com/en-us/library/windows/desktop/ms682100\(v=vs.85\).aspx)
-- system library on Win32 systems.
--
module Network.DNS
    ( -- ** High level API
      queryTXT

      -- * Types
    , Name(..)
    , CharStr(..)
    , IPv4(..)
    , IPv6(..)
    , TTL(..)
    ) where

import           Network.DNS.FFI

-- | Query @TXT@ records (see [RFC 1035, section 3.3.14](https://tools.ietf.org/html/rfc1035#section-3.3.14)).
--
-- >>> queryTXT (Name "_mirrors.hackage.haskell.org")
-- [(TTL 299,["0.urlbase=http://hackage.fpcomplete.com/",
--            "1.urlbase=http://objects-us-west-1.dream.io/hackage-mirror/"])]
--
queryTXT :: Name -> IO [(TTL, [CharStr])]
queryTXT n = do
  recs <- dnsQuery True n DnsTypeTXT
  case recs of
    Left err    -> fail ("DnsQuery_A failed with " ++ show err)
    Right recs' -> pure [ (ttl,ts)
                        | DnsRecord { drTTL = ttl, drData = DnsDataTXT ts } <- recs'
                        ]

