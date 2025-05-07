from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from starlette.requests import Request
from starlette.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from db.session import Base, engine,get_db
from api.v1.endpoints.user import user_router, google_router,facebook_router ,profile_router
Base.metadata.create_all(bind=engine)

app = FastAPI()


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    openapi_schema = FastAPI.openapi(app)  
    openapi_schema["info"]["title"] = "Meal Planner"
    openapi_schema["info"]["version"] = "1.1.0"
    openapi_schema["info"]["description"] = "This API serves as the backend for Meal Planner."
    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(user_router, prefix="/api", tags=["User"])
app.include_router(google_router, tags=["google"])
app.include_router(facebook_router, tags=["facebook"])
app.include_router(profile_router, tags=["profile"])

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", port=8080, reload= True, host="0.0.0.0")


# uvicorn main:app --port 8080 --reload --host 0.0.0.0 --reload




