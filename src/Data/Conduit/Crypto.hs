-- | This module provides a function to decrypt a padded and encrypted
--   stream of 'ByteString's.

{-# LANGUAGE ScopedTypeVariables #-}

module Data.Conduit.Crypto
  ( -- * Decrypt
    decryptPaddedStream
    -- * Re-Export
  , defaultChunkSize
  ) where

import           Control.Exception             (Exception, throw)
import           Crypto.Classes                (BlockCipher, ByteLength, IV, blockSizeBytes)
import           Crypto.Padding                (unpadPKCS5safe)
import           Data.ByteString               (ByteString)
import qualified Data.ByteString               as BS
import           Data.ByteString.Builder.Extra (defaultChunkSize)
import qualified Data.ByteString.Lazy          as BL
import           Data.Conduit                  (ConduitT, yield)
import qualified Data.Conduit.Binary           as CB
import           Data.Tagged                   (Tagged, untag)

-- | Decrypt a PKCS padded and encrypted stream of 'ByteString's
--
-- @
--   runConduitRes $
--     sourceFile inName .|
--     decryptPaddedStream (error "Padding Error") defaultChunkSize (unCbc key) iv .|
--     sinkFile outName
-- @
--
-- /Since 0.3.0/
decryptPaddedStream
  :: forall e cipher m.
     Exception e
  => BlockCipher cipher
  => Monad m
  => e         -- ^ The exception to throw in case of a padding error
  -> Int       -- ^ The chunk size (in Bytes, you may use 'defaultChunkSize', will be modified to be
               --   a guaranteed multiple (at least 1) of the 'blockSizeBytes')
  -> (IV cipher -> ByteString -> (ByteString, IV cipher))
               -- ^ The decrypt function
  -> IV cipher -- ^ The IV (see 'BlockCipher')
  -> ConduitT ByteString ByteString m ()
decryptPaddedStream paddingError chunkSize decrypt = go BS.empty
  where
    go :: ByteString -> IV cipher -> ConduitT ByteString ByteString m ()
    go lastBlock currentIv = do
      (currentBlock, nextIv) <- decrypt currentIv . BL.toStrict <$> CB.take actualBlockSize
      if BS.length currentBlock < actualBlockSize
        then
          case unpadPKCS5safe (lastBlock `BS.append` currentBlock) of
            Just unpadded ->
              yield unpadded
            Nothing ->
              throw paddingError
        else do
          yield lastBlock
          go currentBlock nextIv
    -- the actual block size is probably chunkSize but guaranteed to be a multiple of the cipher block size (at least one)
    actualBlockSize :: Int
    actualBlockSize = ((chunkSize `div` cipherBlockSize) * cipherBlockSize) `max` cipherBlockSize
    -- block size of the cipher (16 in case of AES)
    cipherBlockSize :: Int
    cipherBlockSize = untag (blockSizeBytes :: Tagged cipher ByteLength)
