import abc
from typing import List
from src.core.models import ToolResult

class BaseAdapter(abc.ABC):
    
    @property
    @abc.abstractmethod
    def tool_name(self) -> str:
        pass
        
    @property
    @abc.abstractmethod
    def categories(self) -> List[str]:
        """Returns the list of categories this tool checks."""
        pass
        
    @abc.abstractmethod
    def run(self, repo_path: str) -> ToolResult:
        """Executes the tool against the given repo_path and returns a ToolResult."""
        pass
