from pydantic import BaseModel, ConfigDict

class BaseResponse(BaseModel):
    model_config = ConfigDict(from_attibute=True, arbitary_types_allowed=True)