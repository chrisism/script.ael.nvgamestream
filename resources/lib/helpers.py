import logging

# -- Kodi packages --
import xbmcgui

# --- AKL packages ---
from akl.utils import kodi


class WizardDialog_FileBrowseMultiple(kodi.WizardDialog):
    def __init__(self, decoratorDialog, property_key, title, browseType, filter, shares = 'files',
                 customFunction = None, conditionalFunction = None):
        self.browseType = browseType
        self.filter = filter
        self.shares = shares
        super(WizardDialog_FileBrowseMultiple, self).__init__(
            decoratorDialog, property_key, title, customFunction, conditionalFunction
        )

    def show(self, properties):
        logging.debug(f'WizardDialog_FileBrowseMultiple::show() key = {self.property_key}')
        originalPath = properties[self.property_key] if self.property_key in properties else None

        if callable(self.filter):
            self.filter = self.filter(self.property_key, properties)
        output = xbmcgui.Dialog().browseMultiple(self.browseType, self.title, self.shares, 
            self.filter, False, False, originalPath)

        if not output:
            self._cancel()
            return None
       
        return output
