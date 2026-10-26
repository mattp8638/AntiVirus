# Code-signing certificate (not in git)

Put the Windows code-signing certificate here on the server:

- `codesign.pfx`: the certificate with its private key.
- `codesign.password`: its password. Leave the file empty if the .pfx has none.

Then rebuild. Both files are ignored by git, and the build reads them as BuildKit secrets, so they are never
stored in the image. See docs/CODE_SIGNING.md.
