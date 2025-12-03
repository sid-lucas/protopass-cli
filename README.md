# protopass-cli
Prototype de gestionnaire de mots de passe en ligne de commande, inspiré du modèle de sécurité de Proton Pass.

To Add :
- Add field password -> can use "-pA" to generate strong password
- TOTP
- update vault informations
- alias API simplelogin
- copy to clipboard
- help info that show all the possible type
- help info that show all the required/recommded field for each type
- help info that show all the possible fields
- Show item details more beautifuly (try find inspiration on bitwarden or diskpart or ...)
- Add possibility to use "item field-add" with multiple fields in one command
- (autofill)


To Fix :
- prevent multiple interactive launch
- no vault key fount when : selecting a vault -> quit shell -> get back in shell -> creating new item in vault
- when creating an item with more field than the "required" and "recommended" ones -> ils sont pas prit en compte...
- refresh agent TTL when using general command (and not just by using the agent itself)
- spam log 'session verify' and 'vault list'