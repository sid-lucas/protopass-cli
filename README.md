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
- when creating an item with more field than the "required" and "recommended" ones -> ils sont pas prit en compte...
- spam log 'session verify' and 'vault list'
- When 2 interactive shell, if one have a selected vault, and the other delete that vault -> weird state. Need to check state before interaction with this "ghost" vault, and quit if something went wrong.