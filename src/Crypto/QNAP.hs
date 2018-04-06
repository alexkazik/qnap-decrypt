-- | This is the heart of the qnap-decrypt package. It provides the function
--   to decrypt the files encryped by QNAP's Hybrid Backup Sync.
{-# LANGUAGE ScopedTypeVariables #-}

module Crypto.QNAP
  (
    -- * Decrypt
    decrypt
    -- * Errors
  , DecryptError(..)
  ) where

import           Control.Exception        (Exception (displayException), IOException, catch, handle, throw, throwIO)
import           Control.Monad            (when)
import           Crypto.Cipher.AES128     (AESKey256)
import           Crypto.Classes           (BlockCipher (buildKey, unCbc, unEcb), IV (IV))
import           Data.Binary.Get          (Get, getByteString, getWord64be, runGetOrFail)
import           Data.Bool                (bool)
import           Data.ByteString          (ByteString)
import qualified Data.ByteString          as BS
import qualified Data.ByteString.Lazy     as BL
import qualified Data.ByteString.UTF8     as BSU
import           Data.Conduit             (awaitForever, runConduitRes, yield, (.|))
import           Data.Conduit.Combinators (sinkFile, sourceHandle)
import           Data.Conduit.Zlib        (decompress, defaultWindowBits)
import           Data.Maybe               (fromMaybe, isJust)
import           Data.Streaming.Zlib      (ZlibException)
import           System.Directory         (getFileSize, removeFile)
import           System.IO                (IOMode (ReadMode), withBinaryFile)

import           Data.Conduit.Crypto

-- | Errors the decrypter could run into
--
--   The Exception instance has a specialized 'displayException' function
--   which renders the error in english text (unlike 'show' which just displays the constructor).
--
-- /Since 0.3.0/
data DecryptError
  = PasswordEmpty            -- ^ Password is empty
  | InvalidKey               -- ^ Invalid encryption key
  | UnknownFileType          -- ^ Unknown file type (the file is not encrypted or it's version is not known)
  | BadMagic                 -- ^ Bad Magic (probably wrong password)
  | HeaderDecodeError String -- ^ Error decoding the header: \<error>
  | PaddingError             -- ^ Padding is corrupt (probably damaged file)
  | IOError IOException      -- ^ IO Exception: \<error>
  | ZlibError ZlibException  -- ^ Decompression Exception: \<error> (probably damaged file)
  | FileSizeMismatch         -- ^ File size is different than excepted (probably damaged file)
  deriving (Show)

instance Exception DecryptError where
  displayException PasswordEmpty         = "Password is empty"
  displayException InvalidKey            = "Invalid encryption key"
  displayException UnknownFileType       = "Unknown file type (the file is not encrypted or it's version is not known)"
  displayException BadMagic              = "Bad Magic (probably wrong password)"
  displayException (HeaderDecodeError e) = "Error decoding the header: " ++ e
  displayException PaddingError          = "Padding is corrupt (probably damaged file)"
  displayException (IOError e)           = "IO Exception: " ++ displayException e
  displayException (ZlibError e)         = "Decompression Exception: " ++ displayException e ++ " (probably damaged file)"
  displayException FileSizeMismatch      = "File size is different than excepted (probably damaged file)"

-- Internal structure
newtype QNAPFileType
  = QNAPFileType
    { isCompressed :: Bool
    }

-- | Decrypt a QNAP encoded file (does not throw an exception)
--
-- /Since 0.3.0/
decrypt
  :: String -- ^ The password
  -> FilePath -- ^ The source file
  -> FilePath -- ^ The target file
  -> IO (Maybe DecryptError) -- ^ Returns an error or 'Nothing' in case of a success
decrypt password inName outName = cleanup $ withBinaryFile inName ReadMode $ \inHandle -> do
  when (null password)
    (throwIO PasswordEmpty)
  let
    keyHeader = buildAESKey256 (BSU.fromString (take 32 (cycle password)))
  fileType <- detectFileType <$> BS.hGet inHandle 16
  header <- unEcb keyHeader <$> BS.hGet inHandle 64
  let
    (keyBody, iv, size) =
      runGet'
        HeaderDecodeError
        getFileHeader
        (BL.fromStrict header)
  runConduitRes $
    sourceHandle inHandle .|
    decryptPaddedStream PaddingError defaultChunkSize (unCbc keyBody) iv .|
    (bool (awaitForever yield) (decompress defaultWindowBits) (isCompressed fileType)) .|
    sinkFile outName
  outSize <- getFileSize outName
  when (outSize /= size)
    (throwIO FileSizeMismatch)
  return Nothing
  where
    cleanup action = do
      result <-
        handle (\e -> return (Just (ZlibError e))) $
        handle (\e -> return (Just (IOError e))) $
        handle (\e -> return (Just e)) $
        action
      when (isJust result) $
        removeFile outName `catch` (\(_ :: IOException) -> return ())
      return result

-- Detect file type
detectFileType :: ByteString -> QNAPFileType
detectFileType header
  | header == BS.pack [0x4b, 0xca, 0x94, 0x72, 0x5e, 0x83, 0x1c, 0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] =
      QNAPFileType {isCompressed = False}
  | header == BS.pack [0x4b, 0xca, 0x94, 0x72, 0x5e, 0x83, 0x1c, 0x31, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] =
      QNAPFileType {isCompressed = True}
  | otherwise =
      throw UnknownFileType

-- Read the file header
getFileHeader :: Get (AESKey256, IV cipher, Integer)
getFileHeader = do
  magic <- getByteString 8
  when (magic /= BS.pack [0x4b, 0xca, 0x94, 0x72, 0x5e, 0x83, 0x1c, 0x31])
    (throw BadMagic)
  keyBody <- getByteString 32
  iv <- getByteString 16
  size <- getWord64be
  return (buildAESKey256 keyBody, IV iv, toInteger size)

-- Generate key
buildAESKey256 :: ByteString -> AESKey256
buildAESKey256 = fromMaybe (throw InvalidKey) . buildKey

-- A version of runGet which:
-- 1. raises an exception (instead of error)
-- 2. fails when not all bytes are consumed
runGet' :: Exception e => (String -> e) -> Get a -> BL.ByteString -> a
runGet' ex g b = go (runGetOrFail g b)
  where
    go (Right (bs, _, r))
      | BL.null bs = r
      | otherwise  = throw (ex "Not all bytes are consumed")
    go (Left (_, _, e)) = throw (ex e)
