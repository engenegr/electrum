from electrum.i18n import _
from .qt import OmniCoreRPC

fullname = _('Omni layer transaction viewer')
description = ' '.join([
    _("This plugin allows to view OP_RETURN fields in transaction window.")
])
#requires_wallet_type = ['2of2', '2of3']
available_for = ['qt']
