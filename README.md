# protopass-cli
Prototype de gestionnaire de mots de passe en ligne de commande, inspiré du modèle de sécurité de Proton Pass.

To Add :
- update vault informations
- copy to clipboard
- Show item details more beautifuly (try find inspiration on bitwarden or diskpart or ...)
- (autofill)

To Fix :
- When 2 interactive shell, if one have a selected vault, and the other delete that vault -> weird state. Need to check state before interaction with this "ghost" vault, and quit if something went wrong.

ToDo Workflow/Automations :
- regenerate all the password in a given vault, and putting old password in notes
- auto creation of an employee with a default vault containing default logins for his company's credentials (mail, vpn, other...)