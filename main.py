from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(
    title="Simple SaaS Backend",
    version="1.0"
)

# Test endpoint
@app.get("/")
def root():
    return {"message": "Backend Live"}

# Dummy AI generator endpoint
class GenerateRequest(BaseModel):
    prompt: str

@app.post("/generate")
def generate_text(request: GenerateRequest):
    text = f"Generated text for: {request.prompt}"
    return {"generated_text": text}
