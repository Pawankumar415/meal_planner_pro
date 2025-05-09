from fastapi import FastAPI, HTTPException, Query, Depends, Header, Cookie, Response, Request
from pydantic import BaseModel
from typing import List, Dict, Optional
from fastapi.middleware.cors import CORSMiddleware
import json
import uuid
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
import os
import logging
from dotenv import load_dotenv
import google.generativeai as genai
import re
from db.session import get_db
from fastapi import HTTPException
from typing import List, Dict, Optional
from fastapi import APIRouter
from auth.auth_bearer import JWTBearer
from auth.auth_handler import decodeJWT

import time
import logging
import google.generativeai as genai
from fastapi import HTTPException
from api.v1.models.user.dish_recommendation import UserInteraction

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


# Set the Gemini API key from environment variables
API_KEY = os.getenv("GEMINI_API_KEY")

# app = FastAPI(title="Maitri Rasoi API", description="Indian Meal Planner API")
router = APIRouter()

# Configuration
COOKIE_MAX_AGE = 60 * 60 * 24 * 7  # 7 days in seconds
COOKIE_DOMAIN = None  # Set this to your domain in production


#############################################################



# Region-specific taste profiles
regional_taste_profiles = {
    "North Indian (Punjab, Delhi, UP)": {
        "spices": "Garam masala, cumin, coriander, cardamom, cloves",
        "taste_profile": "Rich, creamy, and moderately spicy with tandoor cooking and dairy components",
        "staple_foods": "Wheat (roti, naan), rice, paneer, rajma, chole"
    },
    "South Indian (Tamil Nadu, Kerala, Karnataka, Andhra)": {
        "spices": "Curry leaves, mustard seeds, asafoetida, tamarind, coconut",
        "taste_profile": "Tangy, sour notes with coconut and distinctive tempering",
        "staple_foods": "Rice, lentils, coconut, seafood (coastal areas)"
    },
    "Gujarati": {
        "spices": "Asafoetida, cumin, coriander, turmeric, cinnamon",
        "taste_profile": "Sweet, salty, and spicy balance with distinct sweetness",
        "staple_foods": "Bajra, jowar, wheat, gram flour, jaggery"
    },
    "Maharashtrian": {
        "spices": "Goda masala, kokum, mustard seeds, asafoetida",
        "taste_profile": "Spicy and robust with kokum sourness",
        "staple_foods": "Jowar, bajra, rice, coconut"
    },
    "Bengali": {
        "spices": "Panch phoron, mustard, nigella seeds, green chili",
        "taste_profile": "Sweet and subtle with mustard oil character",
        "staple_foods": "Rice, fish, mustard, poppy seeds"
    },
    "Rajasthani": {
        "spices": "Red chili, coriander, dried mango powder, cumin",
        "taste_profile": "Spicy, tangy, and robust with minimal water usage",
        "staple_foods": "Bajra, jowar, wheat, gram flour, dairy"
    },
    "Kerala": {
        "spices": "Black pepper, cardamom, cinnamon, cloves, coconut",
        "taste_profile": "Subtle spicing with coconut prominence and seafood variety",
        "staple_foods": "Rice, coconut, seafood, banana, tapioca"
    },
    "Andhra Pradesh": {
        "spices": "Red chilies, tamarind, curry leaves, mustard seeds",
        "taste_profile": "Very spicy with tangy notes from tamarind",
        "staple_foods": "Rice, lentils, vegetables, pickles"
    },
    "Tamil Nadu": {
        "spices": "Black pepper, curry leaves, asafoetida, tamarind",
        "taste_profile": "Spicy with tangy notes and rice-based dishes",
        "staple_foods": "Rice, lentils, tamarind, coconut"
    },
    "Karnataka": {
        "spices": "Byadagi chilies, curry leaves, coconut, tamarind",
        "taste_profile": "Balanced spice with sweet, sour, and hot elements",
        "staple_foods": "Ragi, rice, lentils, coconut"
    },
    "Punjabi": {
        "spices": "Garam masala, cumin, coriander, dried fenugreek leaves",
        "taste_profile": "Rich, buttery, creamy with tandoor influence",
        "staple_foods": "Wheat, dairy, butter, ghee"
    },
    "Himachali": {
        "spices": "Aniseed, dried fenugreek leaves, cardamom, cinnamon",
        "taste_profile": "Subtle and aromatic with yogurt usage",
        "staple_foods": "Wheat, rice, maize, pulses"
    },
    "Goan": {
        "spices": "Kokum, tamarind, red chilies, vinegar, cinnamon",
        "taste_profile": "Tangy, spicy with Portuguese influence and seafood focus",
        "staple_foods": "Rice, seafood, coconut, vinegar"
    },
    "Hyderabadi": {
        "spices": "Cardamom, cloves, cinnamon, star anise, saffron",
        "taste_profile": "Rich, aromatic, and moderately spicy with Nizami influence",
        "staple_foods": "Rice, meat, yogurt, nuts"
    },
    "Kashmiri": {
        "spices": "Fennel, ginger, asafoetida, Kashmiri red chili",
        "taste_profile": "Aromatic, mild heat with yogurt and saffron",
        "staple_foods": "Rice, lamb, yogurt, dried fruits"
    },
    "Assamese": {
        "spices": "Bhut jolokia, pepper, ginger, mustard seeds",
        "taste_profile": "Mild with fermented flavors and minimal spice",
        "staple_foods": "Rice, fish, bamboo shoots, khar"
    },
    "Bihari": {
        "spices": "Panch phoron, asafoetida, bay leaf, turmeric",
        "taste_profile": "Hearty and rustic with sattu prominence",
        "staple_foods": "Sattu, wheat, rice, dairy"
    },
    "Odia": {
        "spices": "Panch phoron, mustard, cumin, fennel",
        "taste_profile": "Subtle, less oil with yogurt and panch phoron",
        "staple_foods": "Rice, seafood, curd, panch phoron"
    }
}



logger = logging.getLogger(__name__)

class GeminiService:
    def __init__(self, api_key):
        # Configure the Gemini API
        self.api_key = api_key
        genai.configure(api_key=api_key)
        self.last_dish_name = None
        self.last_response = None
        # Model parameters optimized for Gemini 2.0-flash
        self.generation_config = {
            "temperature": 0.7,  # Slightly higher temperature for more creative outputs
            "top_p": 0.95,  # High top_p for diverse outputs
            "top_k": 40,  # Reasonable top_k for quality control
            "max_output_tokens": 1024  # Enough tokens for comprehensive responses
        }

    def get_gemini_response(self, prompt, model_name='gemini-2.0-flash'):
        try:
            # Initialize the Gemini model with the optimized generation config
            model = genai.GenerativeModel(model_name)

            # Generate content with the specific generation config
            response = model.generate_content(
                prompt,
                generation_config=self.generation_config
            )

            # Store the response text for later access
            self.last_response = response.text

            # Return the response text
            return response.text
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Gemini API error: {str(e)}")


class MealPlannerService:
    def __init__(self, gemini_service):
        self.gemini_service = gemini_service
        self.regional_profiles = regional_taste_profiles
        self.last_dish_name = None
        self.dish_cache = {}

    def get_regional_profiles(self):
        return self.regional_profiles

    def get_dish_recommendations(self, preferences, previous_dishes=None, regeneration_count=0):
        # Extract regional preference
        region_preference = preferences.get("regional_cuisine", "Any")
        food_preference = preferences.get("food_type", "Any")  # Extract veg/non-veg preference

        # Build the prompt with strong emphasis on regional accuracy and formatting requirements
        regional_specificity = ""
        region_profile = None

        if region_preference and region_preference != "Any":
            # Get taste profile for selected region if available
            for region, profile in self.regional_profiles.items():
                if region_preference.lower() in region.lower():
                    regional_specificity = f"""
                    The user specifically wants {region_preference} cuisine. 
                    This region's taste profile: {profile['taste_profile']}
                    Common spices: {profile['spices']}
                    Staple foods: {profile['staple_foods']}

                    IMPORTANT: ONLY suggest authentic dishes from {region_preference} cuisine. 
                    DO NOT include dishes from other Indian regions.
                    """
                    region_profile = profile
                    break

        # Handle food type preference (veg/non-veg)
        food_type_specificity = ""
        if food_preference and food_preference.lower() != "any":
            if food_preference.lower() == "veg" or food_preference.lower() == "vegetarian":
                food_type_specificity = "ONLY suggest vegetarian dishes. No meat, fish, or eggs."
            elif food_preference.lower() == "non-veg" or food_preference.lower() == "non-vegetarian":
                food_type_specificity = "ONLY suggest non-vegetarian dishes containing meat, chicken, fish, or eggs."

        # Handle previous dishes to avoid
        previous_dishes_str = ""
        if previous_dishes and len(previous_dishes) > 0:
            previous_dishes_str = f"Please AVOID these dishes that were already suggested: {', '.join(previous_dishes)}. "

        # Adjust prompt based on regeneration count
        diversity_emphasis = ""
        if regeneration_count > 0:
            diversity_emphasis = "COMPLETELY DIFFERENT from previous suggestions. Be creative and innovative with your recommendations."

        # Format instructions explicitly for Gemini 2.0-flash
        format_instructions = """
        FORMAT REQUIREMENTS (VERY IMPORTANT):
        - You MUST provide EXACTLY 5 dish recommendations.
        - Format your response as a NUMBERED LIST from 1 to 5.
        - For each dish, provide: number, dish name, colon, then a brief description.
        - Example format:
          1. Dish Name: Brief description including origin.
          2. Another Dish: Brief description including origin.
          [and so on for all 5 dishes]
        - DO NOT include any introductory text or conclusion, ONLY the 5 numbered dishes.
        """

        # Building prompt for dish recommendations with clear structure
        prompt = f"""Based on these preferences: {', '.join([f"{key}: {value}" for key, value in preferences.items()])}, suggest 5 Indian dishes that would be suitable.

        {regional_specificity}
        {food_type_specificity}
        {previous_dishes_str}

        These dishes should be diverse and {diversity_emphasis}
        Include dishes with different main ingredients and cooking methods.

        {format_instructions}
        """

        # Get recommendations from API
        recommendations = self.gemini_service.get_gemini_response(prompt)

        if not recommendations:
            return [], {}, {}

        # Parse recommendations with improved regex patterns
        dish_lines = recommendations.strip().split('\n')
        dishes = []
        descriptions = {}

        # First regex pattern looking for numbered dishes
        numbered_pattern = re.compile(r'^\s*(\d+)\.\s*([^:]+)(?:\s*:\s*(.+))?')
        # Second pattern as backup for unnumbered dishes
        unnumbered_pattern = re.compile(r'^([^:]+)(?:\s*:\s*(.+))?')

        for line in dish_lines:
            line = line.strip()
            if not line:
                continue

            # Try the numbered pattern first
            match = numbered_pattern.search(line)

            if not match:
                # Try the unnumbered pattern as backup
                match = unnumbered_pattern.search(line)

            if match:
                # For numbered pattern: group(1)=number, group(2)=dish_name, group(3)=description
                # For unnumbered pattern: group(1)=dish_name, group(2)=description
                if len(match.groups()) >= 3:  # Numbered pattern matched
                    dish_name = match.group(2).strip()
                    description = match.group(3).strip() if match.group(3) else ""
                else:  # Unnumbered pattern matched
                    dish_name = match.group(1).strip()
                    description = match.group(2).strip() if match.group(2) else ""

                if dish_name and dish_name not in dishes:
                    dishes.append(dish_name)
                    if description:
                        descriptions[dish_name] = description
                        # Cache the description for potential reuse
                        self.dish_cache[dish_name] = description

        # If we still don't have enough dishes, try to extract more aggressively
        if len(dishes) < 5:
            for line in dish_lines:
                line = line.strip()
                if not line or any(dish in line for dish in dishes):
                    continue

                # Try to extract any dish-like name
                potential_dish = re.sub(r'^\d+\.\s*', '', line)
                potential_dish = potential_dish.split(':', 1)[0].strip()

                if potential_dish and len(potential_dish) > 3 and potential_dish not in dishes:
                    dishes.append(potential_dish)
                    # Try to extract a description
                    parts = line.split(':', 1)
                    if len(parts) > 1:
                        descriptions[potential_dish] = parts[1].strip()
                        self.dish_cache[potential_dish] = parts[1].strip()

        # If we still don't have enough dishes, get missing ones
        if len(dishes) < 5:
            missing_count = 5 - len(dishes)
            self._get_additional_dishes(preferences, dishes, descriptions, missing_count)

        # Check if we have cached descriptions for any dishes
        for dish in dishes:
            if dish not in descriptions and dish in self.dish_cache:
                descriptions[dish] = self.dish_cache[dish]
            elif dish not in descriptions:
                # Get a description for this dish
                descriptions[dish] = self.get_dish_description(dish)

        return dishes[:5], descriptions, region_profile  # Take up to 5 dishes

    def _get_additional_dishes(self, preferences, existing_dishes, descriptions, count):
        """Get additional dishes if we didn't get enough from the first request"""
        region_preference = preferences.get("regional_cuisine", "Any")
        food_preference = preferences.get("food_type", "Any")

        # Create a focused prompt for just the missing dishes
        prompt = f"""I need {count} more authentic Indian {region_preference if region_preference != 'Any' else ''} 
        {food_preference if food_preference != 'Any' else ''} dishes.

        I already have these dishes: {', '.join(existing_dishes)}

        Please provide {count} DIFFERENT dishes with brief descriptions.
        Format each as: "Dish Name: Brief description"
        """

        additional_recommendations = self.gemini_service.get_gemini_response(prompt)

        if not additional_recommendations:
            return

        # Parse the additional dishes
        dish_lines = additional_recommendations.strip().split('\n')
        unnumbered_pattern = re.compile(r'^([^:]+)(?:\s*:\s*(.+))?')

        for line in dish_lines:
            line = line.strip()
            if not line:
                continue

            match = unnumbered_pattern.search(line)
            if match:
                dish_name = match.group(1).strip()
                description = match.group(2).strip() if len(match.groups()) > 1 and match.group(2) else ""

                if dish_name and dish_name not in existing_dishes:
                    existing_dishes.append(dish_name)
                    if description:
                        descriptions[dish_name] = description
                        self.dish_cache[dish_name] = description

                    # Stop if we have enough dishes
                    if len(existing_dishes) >= 5:
                        break

    def get_dish_description(self, dish_name):
        """Get a description for a dish if not already available"""
        if dish_name in self.dish_cache:
            return self.dish_cache[dish_name]

        # If not in cache, generate a description
        description_prompt = f"""
        Provide a brief one-sentence description of the Indian dish: {dish_name}.
        Include its origin or regional background if known.
        Keep your response to just one sentence without any preamble or additional text.
        """

        description = self.gemini_service.get_gemini_response(description_prompt)

        # Clean up the description (remove any numbers, extra phrases, etc.)
        description = re.sub(r'^\d+\.\s*', '', description.strip())
        description = description.split('\n')[0].strip()  # Take just the first line

        # Remove any "Description:" or similar prefix
        description = re.sub(r'^[^:]+:\s*', '', description)

        # Cache for future use
        self.dish_cache[dish_name] = description

        return description

    def get_recipe(self, dish):
        self.last_dish_name = dish  # Store the last dish name

        recipe_prompt = f"""Provide a detailed Indian recipe for the dish: {dish}.

        Include:
        1. Ingredients with exact measurements
        2. Step-by-step cooking instructions
        3. Cooking time
        4. A tip for best results
        5. A short note on the dish's origin or cultural significance

        Format the response in clean, readable Markdown with proper headings for each section.
        """

        recipe = self.gemini_service.get_gemini_response(recipe_prompt)

        if not recipe:
            raise HTTPException(status_code=500, detail="Failed to generate recipe")

        return recipe, {}

    def get_recipe_variation(self):
        # Ensure a dish was already requested
        if not self.last_dish_name:
            raise HTTPException(status_code=400, detail="No previous dish found to create a variation for.")

        dish_name = self.last_dish_name

        variation_prompt = f"""Create a creative variation of the Indian dish: {dish_name}.

        Change some ingredients or techniques while preserving its core identity.

        Include:
        1. A catchy name for this variation
        2. Ingredients with exact measurements
        3. Step-by-step instructions
        4. Cooking time
        5. A chef's tip for perfecting this variation

        Format in clean, readable Markdown with proper section headings.
        """

        variation = self.gemini_service.get_gemini_response(variation_prompt)

        if not variation:
            raise HTTPException(status_code=500, detail="Failed to generate a recipe variation")

        return variation


##############################################################

# Initialize services
gemini_service = GeminiService(API_KEY)
meal_planner = MealPlannerService(gemini_service)

# In-memory session store (for dev purposes)
active_sessions = {}

# --- Request & Response Schemas ---

class DietaryPreference(BaseModel):
    dietary_style: str
    people_count: str
    cooking_frequency: str
    allergies: str
    spice_level: str
    regional_cuisine: str
    new_recipes: str


class Dish(BaseModel):
    name: str
    description: Optional[str] = None


class DishRecommendationResponse(BaseModel):
    dishes: List[Dish]
    region_profile: Optional[Dict] = None


class RecipeResponse(BaseModel):
    dish_name: str
    recipe_markdown: str
    region_info: Dict


class RelatedDishesResponse(BaseModel):
    dishes: List[Dish]


class RegionalProfileResponse(BaseModel):
    profiles: Dict[str, Dict]


# New Schema for dish regeneration
class RegenerateDishRequest(BaseModel):
    preferences: DietaryPreference
    keep_dishes: List[str]
    replace_dish: str


@router.get("/regions", response_model=RegionalProfileResponse)
async def get_regional_profiles():
    return {"profiles": meal_planner.get_regional_profiles()}


#  new code by bhavan kumar


def get_current_user_id(token: str = Depends(JWTBearer())):
    payload = decodeJWT(token)
    user_id: int = payload.get('user_id')
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not retrieve user ID from token"
        )
    return user_id


def get_session_id_from_cookie(
    request: Request,
    response: Response,
    session_id_cookie: Optional[str] = Cookie(None, alias="session_id")
):
    session_id = session_id_cookie if session_id_cookie else str(uuid.uuid4())
    response.set_cookie(
        key="session_id",
        value=session_id,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https",
        # domain=COOKIE_DOMAIN
    )
    return session_id




@router.post("/recommend-dishes", response_model=DishRecommendationResponse)
async def recommend_dishes(
    request: Request,
    response: Response,
    preferences: DietaryPreference,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
    session_id: str = Depends(get_session_id_from_cookie), 
    previous_dishes: Optional[List[str]] = Query(None),
    regeneration_count: int = Query(0)
):

    
    logger.info(f"Processing dish recommendation for user: {current_user_id}, session: {session_id}")

    preferences_dict = preferences.dict()

    dishes, descriptions, region_profile = meal_planner.get_dish_recommendations(
        preferences_dict,
        previous_dishes=previous_dishes,
        regeneration_count=regeneration_count
    )

    dish_objects = [Dish(name=d, description=descriptions.get(d, "")) for d in dishes]

    response_data = DishRecommendationResponse(
        dishes=dish_objects,
        region_profile=region_profile
    )

    # Store interaction in database
    db_interaction = UserInteraction(
        user_id=current_user_id,
        session_id=session_id,
        user_input=json.dumps(preferences_dict),
        response=json.dumps(response_data.dict())
    )
    db.add(db_interaction)
    db.commit()

    return response_data

# New endpoint for regenerating specific dishes


# Define a Pydantic model for input validation
class ReplaceDishRequest(BaseModel):
    replace_dish: str


# this end point updated by bhavan kumar


@router.post("/regenerate-dish", response_model=DishRecommendationResponse)
async def regenerate_dish(
    request: Request,
    response: Response,
    replace_dish_request: ReplaceDishRequest,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
    session_id: str = Depends(get_session_id_from_cookie)
):
    replace_dish = replace_dish_request.replace_dish.strip()  # Trim whitespace

    logger.info(f"Regenerating dish for user: {current_user_id}, session: {session_id}")
    logger.info(f"Replacing dish: {replace_dish}")

    latest_interaction = db.query(UserInteraction) \
        .filter(UserInteraction.user_id == current_user_id) \
        .filter(UserInteraction.session_id == session_id) \
        .order_by(UserInteraction.id.desc()) \
        .first()

    if not latest_interaction:
        raise HTTPException(status_code=400, detail="No previous recommendation found")

    previous_response = json.loads(latest_interaction.response)
    previous_input = json.loads(latest_interaction.user_input)

    if isinstance(previous_input, dict):
        preferences_dict = previous_input.get("preferences", previous_input)
    else:
        raise HTTPException(status_code=400, detail="Invalid previous input format")

    previous_dish_objects = previous_response.get("dishes", [])
    previous_dishes = [dish["name"] for dish in previous_dish_objects]

    # Setup for fuzzy matching
    found_match = False
    dish_to_replace = None

    # Try exact match first
    if replace_dish in previous_dishes:
        dish_to_replace = replace_dish
        found_match = True
    else:
        # Try case-insensitive match
        for dish in previous_dishes:
            if dish.lower() == replace_dish.lower():
                dish_to_replace = dish
                found_match = True
                break

        # If still no match, try partial match (if user entered part of the dish name)
        if not found_match:
            for dish in previous_dishes:
                if replace_dish.lower() in dish.lower() or dish.lower() in replace_dish.lower():
                    dish_to_replace = dish
                    found_match = True
                    break

    if not found_match:
        # Show available dishes in the error to help the user
        available_dishes = ", ".join([f"'{dish}'" for dish in previous_dishes])
        raise HTTPException(
            status_code=400,
            detail=f"Dish '{replace_dish}' not found in previous recommendations. Available dishes: {available_dishes}"
        )

    dish_index_to_replace = previous_dishes.index(dish_to_replace)
    keep_dish_objects = [dish for dish in previous_dish_objects if dish["name"] != dish_to_replace]

    # Get multiple dish recommendations to ensure we get a new unique one
    dishes_to_exclude = previous_dishes  # Exclude ALL previous dishes to force new suggestions
    new_dishes, new_descriptions, region_profile = meal_planner.get_dish_recommendations(
        preferences_dict,
        previous_dishes=dishes_to_exclude,
        regeneration_count=3  # Ask for multiple dishes to increase chances of finding a new one
    )

    if not new_dishes:
        raise HTTPException(status_code=500, detail="Failed to generate new dish recommendations")

    # Make sure we select a truly new dish
    selected_dish = None
    for dish in new_dishes:
        if dish not in previous_dishes:
            selected_dish = dish
            break

    # If we somehow didn't get any unique dishes, force at least a different dish
    if not selected_dish:
        # Try again with a different seed or approach
        try:
            # Use a direct call to get a single replacement dish
            alternative_dishes = meal_planner.get_alternative_dish(
                preferences_dict,
                exclude_dishes=previous_dishes
            )
            if alternative_dishes and len(alternative_dishes) > 0:
                selected_dish = alternative_dishes[0]
        except:
            # If alternative method fails, just use the first recommendation
            # even if it's not ideal
            selected_dish = new_dishes[0]

    # Last resort - if we still have no dish, raise an error
    if not selected_dish or selected_dish == dish_to_replace:
        raise HTTPException(
            status_code=500,
            detail="Unable to generate a unique replacement dish. Please try again."
        )

    # Create the new dish object
    new_dish_object = {
        "name": selected_dish,
        "description": new_descriptions.get(selected_dish, "") or meal_planner.get_dish_description(selected_dish)
    }

    # Insert the new dish at the same position as the replaced dish
    final_dish_objects = keep_dish_objects.copy()
    final_dish_objects.insert(dish_index_to_replace, new_dish_object)

    # Verify replacement was successful
    final_dish_names = [dish["name"] for dish in final_dish_objects]
    if dish_to_replace in final_dish_names:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to replace dish '{dish_to_replace}'. Please try again."
        )
    if selected_dish not in final_dish_names:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to add new dish '{selected_dish}'. Please try again."
        )

    dish_objects = [Dish(name=d["name"], description=d["description"]) for d in final_dish_objects]

    response_data = DishRecommendationResponse(
        dishes=dish_objects,
        region_profile=region_profile if region_profile else previous_response.get("region_profile", {})
    )

    db_interaction = UserInteraction(
        user_id=current_user_id, 
        session_id=session_id,
        user_input=json.dumps({
            "action": "regenerate_dish",
            "preferences": preferences_dict,
            "replace_dish": dish_to_replace,
            "new_dish": selected_dish
        }),
        response=json.dumps(response_data.dict())
    )
    db.add(db_interaction)
    db.commit()

    return response_data



@router.get("/recipe/{dish_name}", response_model=RecipeResponse)
async def get_dish_recipe(
    dish_name: str,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id), 
    session_id: str = Depends(get_session_id_from_cookie) 
):
    # Log session information
    logger.info(f"Getting recipe for dish: {dish_name}, user: {current_user_id}, session: {session_id}")

    recipe, region_info = meal_planner.get_recipe(dish_name)

    response_data = RecipeResponse(
        dish_name=dish_name,
        recipe_markdown=recipe,
        region_info=region_info
    )

    # Store interaction in database
    db_interaction = UserInteraction(
        user_id=current_user_id,
        session_id=session_id,
        user_input=json.dumps({"dish_name": dish_name}),
        response=recipe
    )
    db.add(db_interaction)
    db.commit()

    return response_data




# updated by bhavan kumar 



@router.get("/recipe-variation")
async def get_recipe_variation(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user_id: int = Depends(get_current_user_id),
    session_id: str = Depends(get_session_id_from_cookie)
):
    # Log session information
    logger.info(f"Getting recipe variation for user: {current_user_id}, session: {session_id}")

    variation = meal_planner.get_recipe_variation()

    # Store interaction in database
    db_interaction = UserInteraction(
        user_id=current_user_id,
        session_id=session_id,
        user_input=json.dumps({"request": "recipe_variation", "dish": meal_planner.last_dish_name}),
        response=variation
    )
    db.add(db_interaction)
    db.commit()

    return {"recipe_variation": variation}

