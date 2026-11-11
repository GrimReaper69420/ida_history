from collections import defaultdict
from typing import Dict, List, Any
from datetime import datetime
from enum import Enum
import pickle
import idc
import ida_idp
from pathlib import Path 

from ida_history.html_template import HTML_TEMPLATE

# External imports
from jinja2 import Environment, BaseLoader

# Thinking aboyt a format lets just create hirachy of data
# Dict1 of Dict2 of ARRAYS
# Dict1 --> Would store the Event Type
# Dict2 --> Would store the Address
# array Of Dicts --> Would store the Event details

# Thinking of storing each event type in a different form with optional parameters
# {"Event Type":
#   {Address: [
#            {"Type":"value", ...}
#            ] }
# }


# In the end gonna Append all the history inside of a text file too
# Naming Convention for the 1- (Pickle Dict struct log) & 2- (Simple incrementel history list) is gonna be
# (Pickle Dict struct log)     --> (Binary_name).log
# (Simple incrementel history list) --> (Binary_name)_history.txt

_TYPE_CHANGE_MAP = {
    ida_idp.LTC_ADDED: "TYPE_ADDED"
    ,ida_idp.LTC_DELETED: "TYPE_DELETED"
    ,ida_idp.LTC_EDITED: "TYPE_EDITED"
    ,ida_idp.LTC_ALIASED: "TYPE_ALIASED"
    ,ida_idp.LTC_COMPILER: "TYPE_COMPILER"
    ,ida_idp.LTC_TIL_LOADED: "TIL_LOADED"
    ,ida_idp.LTC_TIL_UNLOADED: "TIL_UNLOADED"
    ,ida_idp.LTC_TIL_COMPACTED: "ORDINAL_COMPACTED"
}

class CategoryEnum(Enum):
    # Event Types
    FUNCTION = "evt.function"
    COMMENT = "evt.comment"
    SEGMENT = "evt.segment"
    RENAME = "evt.rename"
    BYTES = "evt.bytes"
    TYPE_CHANGE = "evt.type_change"

    # Hook catagory ENums for Types Filds
    IDB_HOOK = "evt.IDB_HOOK"
    HEXRAYS_HOOK = "evt.HEXRAYS_HOOK"

    # Subcatagory of events
    CREATION = "evt.creation"
    DELETION = "evt.deletion"

def _inner_dict_factory():
    return defaultdict(list)

class ida_history_format():
# The _instance is for the object creation and then not allowing it to reinitialize later on
# Thus multiple initializations of this same class would result in the same object being used.
# This was done to avoid opening the pickle log multiple time and possible other conflicts
# THere can be better solutions but this i found good

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self, file_path=None):
        if self.initialized:
            return

        # Generator
        self.generator = HTMLReportGenerator()

        # Internal structs for data
        self.old_func_names: Dict[int, str] = {}
        self.old_comments: Dict[int, str] = {}
        self.events: Dict[CategoryEnum, Dict[int, List[Dict[str, Any]]]] = defaultdict(_inner_dict_factory)

        # External Structs to save/dump data
        self.logs_struct: List[Dict[any, any]] = {
            "old_func_names": self.old_func_names
            ,"old_comments": self.old_comments
            ,"events": self.events
        }

        if (file_path is not None):
            self.idb_path = file_path
        else:
            self.idb_path = idc.get_idb_path()[:-4] + ".log"
        self.history_list = self.idb_path[:-4] + "_history.txt"
        self.initialized = True

#(NOTE) Logging Print to Remove
        print(f"[History] IDA log struct stored at: {self.idb_path}")
        print(f"[History] history list Stored in: {self.history_list}")
        
        self.load_data()

############################################################################
# FOr Internal use mostly, as I dont wanna mess up the even Struct manually
################################################################################
    def load_data(self, file_path=None):
        """Safely loads data. If file doesn't exist, simply starts with an empty history."""
        if (file_path is not None):
            self.idb_path = file_path

        # Step 1: Check if path exists
        if not self.idb_path:

#(NOTE) Logging Print to Remove
            print(f"[History] File '{self.idb_path}' not found. Starting with fresh history.")

            return
        try:
            with open(self.idb_path, "rb") as f:
                self.logs_struct = pickle.load(f)
                self.events = self.logs_struct["events"]
                self.old_func_names = self.logs_struct["old_func_names"]
                self.old_comments = self.logs_struct["old_comments"]

        except (pickle.PickleError, EOFError, Exception) as e:

#(NOTE) Logging Print to Remove
            # Prevents crashing if the file is empty, corrupted, or invalid
            print(f"[History] Failed to load history file ({e}). Starting fresh.")

            self.save_data()

    def get_old_func_names(self):
        return self.old_func_names

    def set_old_func_names(self, func_names):
        self.old_func_names = func_names

    def get_old_comments(self):
        return self.old_comments
    
    def set_old_comments(self, comments):
        self.old_comments = comments

    def save_data(self, file_path=None):
        """Serialize and save self.events to disk."""
        
        # Update file path if a new one is provided
        if file_path is not None:
            self.idb_path = file_path

        # Ensure we actually have a path to save to
        if not hasattr(self, 'idb_path') or not self.idb_path:
            raise ValueError("No file path specified to save history.")
        with open(self.idb_path, "wb") as f:
            pickle.dump(self.logs_struct, f)

    def log_history(self, message):
        """Append a message to the history log."""

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(self.history_list, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {message}\n")


######################################
# Mostly External Methods
######################################
    def add_event(self, category: CategoryEnum, address: int, event_data: dict):
        """Add a history change event to a specific category and memory address (ea_t)."""

        message = f"[History] --> {category.value} at {hex(address)}: {event_data}"

#(NOTE) Logging Print to Remove 
        print(message)

        self.events[category][address].append(event_data)
        self.save_data()
        self.log_history(message)

    def get_address_history(self, category: CategoryEnum, address: int) -> List[dict]:
        """Fetch all events for a specific category and address."""
        return self.events[category].get(address, [])

    def get_category_history(self, category: CategoryEnum) -> Dict[int, List[dict]]:
        """Fetch all events for a specific category."""
        return self.events[category]

    def generate_report(self):
        self.generator.generate(self.events, self.idb_path)


### Generator for HTML file
class HTMLReportGenerator:
    def __init__(self, title="IDA History Report"):
        self.title = title

        self.env = Environment(
            loader=BaseLoader(),
            autoescape=True,
        )

        self.template = self.env.from_string(HTML_TEMPLATE)
        print(self.template)

    @staticmethod
    def _normalize_events(events):
        """
        Convert CategoryEnum keys to their .value.

        Supports both:
            {
                CategoryEnum.BYTES: {...}
            }

        and:

            {
                "evt.bytes": {...}
            }
        """
        normalized = {}

        for category, addresses in events.items():
            normalized[str(category)] = addresses

        return normalized

    def generate(self, events, output_file, name="ida_history_report"):
        report_path = Path(output_file).parent / f"{name}.html"
        print(f"[+] Output file: {report_path}")


        """
        Generate a single-page HTML report.

        Expected structure:

        {
            CategoryEnum.BYTES: {
                0x13A8: [
                    {
                        "TYPE": "IDB_HOOK",
                        "old_value": "0x40"
                    }
                ]
            },

            CategoryEnum.COMMENT: {
                0x13F9: [
                    {
                        "TYPE": "IDB_HOOK",
                        "comment": "n",
                        "kind": "repeatable",
                        "remarks": "Comment was Added"
                    }
                ]
            }
        }
        """
        events = self._normalize_events(events)

        html = self.template.render(
            title=self.title,
            events=events,
        )

        if isinstance(report_path, Path):
            print("[i] Valid path instance")
        else:
            print("[!] FAAAAAAAAAAAAAAAK")

        report_path.write_text(
            html,
            encoding="utf-8",
        )