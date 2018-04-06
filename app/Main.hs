{-# LANGUAGE RecordWildCards #-}

module Main
  ( main
  ) where

import           Control.Exception   (displayException)
import           Control.Monad       (void, when)
import           Data.Semigroup      ((<>))
import qualified Options.Applicative as O
import           System.Directory    (createDirectoryIfMissing, doesDirectoryExist, doesFileExist, listDirectory,
                                      renameFile)
import           System.FilePath     (takeDirectory, takeFileName, (</>))
import           System.IO           (hClose, hPutStrLn, openBinaryTempFile, stderr)

import           Crypto.QNAP         (decrypt)

data Command
  = Command
    { commandSingleFile  :: Bool
    , commandInline      :: Bool
    , commandPassword    :: String
    , commandSource      :: String
    , commandDestination :: String
    , commandVerbose     :: Bool
    }
  deriving (Show)

command :: O.Parser Command
command =
  O.hsubparser $
    O.command
      "dir"
      ( O.info
          parseDirectory
          (O.progDesc "decrypt a directory")
      ) <>
    O.command
      "dir-in-place"
        ( O.info
            parseDirectoryInPlace
            (O.progDesc "decrypt a directory in place")
        ) <>
    O.command
      "file"
        ( O.info
            parseFile
            (O.progDesc "decrypt a file")
        ) <>
    O.command
      "file-in-place"
        ( O.info
            parseFileInPlace
            (O.progDesc "decrypt a file in place")
        )
  where
    parseDirectory =
      Command False False
        <$> O.strOption
          (  O.long "password"
          <> O.short 'p'
          <> O.metavar "PASS"
          <> O.help "Password"
          )
        <*> O.strOption
          (  O.long "source"
          <> O.short 's'
          <> O.metavar "SRC"
          <> O.help "Directory to be decrypted"
          )
        <*> O.strOption
          (  O.long "destination"
          <> O.short 'd'
          <> O.metavar "DST"
          <> O.help "Directory to store the decrypted files"
          )
        <*> O.switch
          (  O.long "verbose"
          <> O.short 'v'
          <> O.help "Print all decrypted files"
          )
    parseDirectoryInPlace =
      Command False True
        <$> O.strOption
          (  O.long "password"
          <> O.short 'p'
          <> O.metavar "PASS"
          <> O.help "Password"
          )
        <*> O.strOption
          (  O.long "directory"
          <> O.short 'd'
          <> O.metavar "DIR"
          <> O.help "Directory to be decrypted in place"
          )
        <*> pure ""
        <*> O.switch
          (  O.long "verbose"
          <> O.short 'v'
          <> O.help "Print all decrypted files"
          )
    parseFile =
      Command True False
        <$> O.strOption
          (  O.long "password"
          <> O.short 'p'
          <> O.metavar "PASS"
          <> O.help "Password"
          )
        <*> O.strOption
          (  O.long "source"
          <> O.short 's'
          <> O.metavar "SRC"
          <> O.help "File to be decrypted"
          )
        <*> O.strOption
          (  O.long "destination"
          <> O.short 'd'
          <> O.metavar "DST"
          <> O.help "File/directory to store the decrypted file"
          )
        <*> O.switch
          (  O.long "verbose"
          <> O.short 'v'
          <> O.help "Print all decrypted files"
          )
    parseFileInPlace =
      Command True True
        <$> O.strOption
          (  O.long "password"
          <> O.short 'p'
          <> O.metavar "PASS"
          <> O.help "Password"
          )
        <*> O.strOption
          (  O.long "file"
          <> O.short 'f'
          <> O.metavar "FILE"
          <> O.help "File to be decrypted in place"
          )
        <*> pure ""
        <*> O.switch
          (  O.long "verbose"
          <> O.short 'v'
          <> O.help "Print all decrypted files"
          )

main :: IO ()
main = do
  Command{..} <-
    O.execParser $
      O.info (command O.<**> O.helper)
        (  O.fullDesc
        <> O.progDesc "Decrypt QNAP files/folders"
        <> O.footer "WARNING: The target file/directory will be overwritten"
        )
  case (commandSingleFile, commandInline) of
    (False, False) -> cmdDir commandVerbose commandPassword [(commandSource, commandDestination)]
    (False, True)  -> cmdDirInPlace commandVerbose commandPassword [commandSource]
    (True, False)  -> cmdFile commandVerbose commandPassword commandSource commandDestination
    (True, True)   -> cmdFileInPlace commandVerbose commandPassword commandSource

cmdDir :: Bool -> String -> [(FilePath, FilePath)] -> IO ()
cmdDir verbose pass = go
  where
    go [] = return ()
    go ((src, dst):stack) = do
      isFile <- doesFileExist src
      isDir <- doesDirectoryExist src
      case (isFile, isDir) of
        (True, False) -> do
          cmdFile verbose pass src dst
          go stack
        (False, True) -> do
          files <- listDirectory src
          createDirectoryIfMissing True dst
          go (map (\file -> (src </> file, dst </> file)) files ++ stack)
        _ ->
          return ()

cmdDirInPlace :: Bool -> String -> [FilePath] -> IO ()
cmdDirInPlace verbose pass = go
  where
    go [] = return ()
    go (entry:stack) = do
      isFile <- doesFileExist entry
      isDir <- doesDirectoryExist entry
      case (isFile, isDir) of
        (True, False) -> do
          cmdFileInPlace verbose pass entry
          go stack
        (False, True) -> do
          files <- listDirectory entry
          go (map (entry </>) files ++ stack)
        _ ->
          return ()

cmdFile :: Bool -> String -> FilePath -> FilePath -> IO ()
cmdFile verbose pass src dst = do
  dstIsDir <- doesDirectoryExist dst
  let
    dst' =
      if dstIsDir
        then dst </> takeFileName src
        else dst
  void $ decrypt' verbose pass src dst'

cmdFileInPlace :: Bool -> String -> FilePath -> IO ()
cmdFileInPlace verbose pass file = do
  (tempFileName, tmpHandle) <- openBinaryTempFile (takeDirectory file) (takeFileName file ++ ".temp.qnap")
  hClose tmpHandle
  success <- decrypt' verbose pass file tempFileName
  -- the decrypt removes the output file in case of an error -> no need to do it here also
  when success $
    renameFile tempFileName file

decrypt' :: Bool -> String -> FilePath -> FilePath -> IO Bool
decrypt' verbose pass src dst = do
  result <- decrypt pass src dst
  case result of
    Just err -> do
      hPutStrLn stderr (src ++ ": " ++ displayException err)
      return False
    Nothing -> do
      when verbose $
        hPutStrLn stderr (src ++ ": OK")
      return True
