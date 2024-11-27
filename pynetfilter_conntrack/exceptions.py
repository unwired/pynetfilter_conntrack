
class GenericNFCTError(Exception):
    "Base class for NFCT errors, not further specified"
    pass

class ConntrackEntryExistsError(GenericNFCTError):
    "Raised when attempting to create an entry that already exists"
    pass

class ConntrackEntryNotFoundError(GenericNFCTError):
    "Raised when attempting to get or update an entry that doesn't exist"
    pass

