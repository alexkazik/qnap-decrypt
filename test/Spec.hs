{-# LANGUAGE ScopedTypeVariables #-}

import           Control.Exception    (IOException, catch)
import           Control.Monad        (forM_)
import qualified Data.ByteString.Lazy as BL
import           Data.Maybe           (isNothing)
import           System.Directory     (listDirectory, removeFile)
import           System.FilePath      ((</>))
import           System.IO            (hClose)
import           System.IO.Temp       (withSystemTempFile)
import           Test.Hspec           (describe, hspec, it, shouldSatisfy)
import           Test.HUnit.Base      ((@?))

import           Crypto.QNAP

encryptedDirectory :: FilePath
encryptedDirectory = "test/encrypted"

referenceDirectory :: FilePath
referenceDirectory = "test/reference"

password :: String
password = "qORFZQiilzCz5JIxiOOuVE2TsJ6Xn5Rk"

main :: IO ()
main =
  withSystemTempFile "decrypt" $ \tempFile tempFileHandle -> do
    hClose tempFileHandle
    files <- listDirectory encryptedDirectory
    hspec $ describe "Crypto.QNAP.dectypt" $
      forM_ files $ \file -> it ("Verify file " ++ file) $ do
        removeFile tempFile `catch` (\(_ :: IOException) -> return ())
        decrypt password (encryptedDirectory </> file) tempFile >>= (`shouldSatisfy` isNothing)
        decrypted <- BL.readFile tempFile
        reference <- BL.readFile (referenceDirectory </> file)
        decrypted == reference @? "Decrypted file does not match reference"
