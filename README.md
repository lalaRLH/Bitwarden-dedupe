Removes duplicates within the Bitwarden Vault (required after importing from multiple places e.g. iCloud Keychain and another password manager)

How grouping works: two entries are treated as duplicates if they share the same primary domain (scheme/www/trailing slashes stripped) and username. Items with no URL fall back to matching on name + username. Non-login items (cards, identities, notes) group by type + exact name only, to be conservative.
What gets merged across duplicates:

Password: first non-empty value wins
Passkeys / FIDO2 credentials — unioned by credentialId
TOTP: first non-empty wins
URIs: full union, deduped by normalised URL
Notes: concatenated with a divider if both are non-empty
Custom fields: merged by field name, non-empty value preferred
Password history: full union
Favourite flag: set if either duplicate had it flagged

Example usage:
Export .json output from Bitwarden Vault: https://vault.bitwarden.com and then pass it through the script. 
python3 bw_dedupe.py my_export.json cleaned.json  # custom output name
No dependencies or requirements other than python on macOS 26. 

NOTE: Tested on my personal vault using Version 2026.2.1 (57189) of Bitwarden. I offer no warranties, no support, no guarantees and/or I am not liable for any damage to a Bitwarden vault from the usage of this python script. *Proceed at your own risk and please, keep a seperate backup of your vault*
