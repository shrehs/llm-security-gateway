from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    prompt: str = Field(min_length=1)
    model: str = Field(default="llama3", min_length=1)
    user_id: str = "demo-user"
    role: str = "employee"
    department: str = "general"
    clearance: str = "public"
