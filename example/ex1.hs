{-# LANGUAGE OverloadedStrings #-}

module Main where

import Network.DNS

main :: IO ()
main = do
  print =<< queryA (Name "localhost")
  print =<< queryAAAA (Name "localhost")
  print =<< queryA (Name "git.haskell.org")
  print =<< queryAAAA (Name "git.haskell.org")
  print =<< queryA (Name "www.google.com")
  print =<< queryAAAA (Name "www.google.com")
  print =<< queryCNAME (Name "hackage.haskell.org")
  print =<< querySRV (Name "_imap._tcp.gmail.com")
  print =<< querySRV (Name "_sip._udp.sip.voice.google.com")
  print =<< queryTXT (Name "_mirrors.hackage.haskell.org")
