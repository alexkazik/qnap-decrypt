qnap-decrypt
============

A program (and library) to decrypt files encoded by QNAP's Hybrid Backup Sync.


Installation
------------

1. [Install Stack](https://docs.haskellstack.org/en/stable/install_and_upgrade/)
2. Download/clone this repo
3. `cd` into it
4. `stack install`

    - You may have to add the path of the installation to your PATH or always use the full path


Usage
-----

The program supports four modes:

- Decrypt a single file or
- Decrypt a full directory tree
- Replace the decrypted file(s) or
- Save the file/directory to a new file/directory

Example:

```
qnap-decrypt file -p password -s source.file -d target.file
```


Thanks
------

- [Mikiya83](https://github.com/Mikiya83) for hbs_decipher which I used to learn about the file structure
