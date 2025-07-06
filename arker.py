import os
import json
import datetime
import requests
import logging
import threading
import time
import schedule
from pathlib import Path
from typing import List, Dict, Any, Optional
import speech_recognition as sr
from pygame import mixer
from gtts import gTTS
from dotenv import load_dotenv
import google.generativeai as genai
from groq import Groq
from sentence_transformers import SentenceTransformer
import faiss
import numpy as np
import pickle
import whois
import sublist3r
from shodan import Shodan
import nmap
from bs4 import BeautifulSoup
import re

# Configure logging
logging.basicConfig(
    filename='arker.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ArkerAI:
    def __init__(self, gemini_api_key: str, grok_api_key: str, openweathermap_api_key: str, news_api_key: str, data_dir: str = "arker_data"):
        """Initialize Arker AI Assistant with EDITH-inspired capabilities."""
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)

        # API keys
        try:
            genai.configure(api_key=gemini_api_key)
            self.gemini_model = genai.GenerativeModel('gemini-1.5-flash')
            self.grok_client = Groq(api_key=grok_api_key)
            self.openweathermap_api_key = openweathermap_api_key
            self.news_api_key = news_api_key
            self.shodan_api = Shodan(os.getenv("SHODAN_API_KEY")) if os.getenv("SHODAN_API_KEY") else None
            self.virustotal_client = vt.Client(os.getenv("VIRUSTOTAL_API_KEY")) if os.getenv("VIRUSTOTAL_API_KEY") else None
        except Exception as e:
            logger.error(f"API initialization failed: {e}")
            raise ValueError(f"Failed to initialize APIs. Check keys and connectivity: {e}")

        # Initialize STT
        try:
            self.recognizer = sr.Recognizer()
            self.microphone = sr.Microphone()
        except Exception as e:
            logger.error(f"STT initialization failed: {e}")
            raise ValueError(f"Could not find PyAudio; check installation: {e}")

        # Wake phrases detection
        self.wake_phrases = ["hey bro", "hey buddy", "hey", "hello", "arker", "macha", "mama"]
        self.sleep_command = "arker go back to sleep"
        self.is_active = False
        self.listening_for_wake_word = True

        # Sentence transformer
        try:
            self.sentence_model = SentenceTransformer('all-MiniLM-L6-v2')
        except Exception as e:
            logger.error(f"Sentence transformer initialization failed: {e}")
            raise ValueError(f"Failed to initialize sentence transformer: {e}")

        # File paths
        self.conversations_file = self.data_dir / "conversations.json"
        self.tasks_file = self.data_dir / "tasks.json"
        self.reminders_file = self.data_dir / "reminders.json"
        self.vector_db_file = self.data_dir / "vector_db.pkl"
        self.faiss_index_file = self.data_dir / "faiss_index.idx"

        # Data structures
        self.conversations = []
        self.tasks = []
        self.reminders = []
        self.vector_db = []
        self.faiss_index = None

        # Load data
        self.load_data()

        # Initialize vector DB
        self.initialize_vector_db()

        # User context
        self.user_context = {
            "preferences": {},
            "frequent_topics": {},
            "conversation_history": []
        }

        # Conversation chain
        self.conversation_chain = []

        # Setup tools
        self.setup_tools()

        # Start reminder scheduler
        self.start_reminder_scheduler()

        logger.info("Arker AI Assistant initialized successfully, boss!")

    def setup_tools(self):
        """Setup tools for ethical hacking, task management, weather, news, etc."""
        try:
            self.tools = [
                {"name": "add_task", "func": self.agent_add_task, "description": "Add task: description,due_date,priority"},
                {"name": "get_tasks", "func": self.agent_get_tasks, "description": "Get tasks: all, pending, completed, in_progress"},
                {"name": "list_tasks", "func": self.agent_list_tasks, "description": "List all tasks"},
                {"name": "update_task", "func": self.agent_update_task, "description": "Update task: task_id,new_status"},
                {"name": "add_reminder", "func": self.agent_add_reminder, "description": "Add reminder: text,time (HH:MM)"},
                {"name": "get_reminders", "func": self.agent_get_reminders, "description": "Get active reminders"},
                {"name": "search_conversations", "func": self.agent_search_conversations, "description": "Search conversations: query"},
                {"name": "get_weather", "func": self.agent_get_weather, "description": "Get weather: city"},
                {"name": "get_news", "func": self.agent_get_news, "description": "Get news headlines"},
                {"name": "whois_lookup", "func": self.agent_whois_lookup, "description": "WHOIS lookup: domain"},
                {"name": "subdomain_enum", "func": self.agent_subdomain_enum, "description": "Enumerate subdomains: domain"},
                {"name": "google_dork", "func": self.agent_google_dork, "description": "Generate Google dork: query"},
                {"name": "shodan_search", "func": self.agent_shodan_search, "description": "Search IoT devices: query"},
                {"name": "vuln_scan", "func": self.agent_vuln_scan, "description": "Scan for vulnerabilities: url"},
                {"name": "port_scan", "func": self.agent_port_scan, "description": "Scan ports: host,optional_port_range (e.g., 1-1000)"},
                {"name": "crawl_website", "func": self.agent_crawl_website, "description": "Crawl website: url"},
                {"name": "threat_intel", "func": self.agent_threat_intel, "description": "Threat intelligence: target"}
            ]
            logger.info("Hacking tools initialized successfully, boss!")
        except Exception as e:
            logger.error(f"Tool setup failed: {e}")
            raise RuntimeError(f"Failed to setup tools: {e}")

    def agent_port_scan(self, input_string: str) -> str:
        """Perform port scan on a host with optional port range."""
        try:
            parts = input_string.lower().replace("port scan ", "").strip().split(',')
            host = parts[0].strip()
            port_range = parts[1].strip() if len(parts) > 1 else "1-1000"
            if not host or not re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$|^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$", host):
                return "Invalid host format, boss. Use IP or domain (e.g., scanme.nmap.org)."
            nm = nmap.PortScanner()
            nm.scan(host, arguments=f'-sS -T4 -p {port_range}')
            if not nm.all_hosts():
                return f"No open ports found for {host}, boss."
            result = nm.csv()
            return f"Port scan complete, boss:\n{result[:500]}"
        except Exception as e:
            logger.error(f"Port scan error for {host}: {e}")
            return f"Port scan failed for {host}, boss. Ensure permission and valid port range."

    def agent_crawl_website(self, input_string: str) -> str:
        """Crawl a website for OSINT with URL validation."""
        try:
            url = input_string.lower().replace("crawl website ", "").strip()
            if not url or not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url):
                return "Invalid URL format, boss. Use http:// or https://example.com."
            if not url.startswith(('http://', 'https://')):
                url = f"https://{url}"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text(separator=' ', strip=True)
            result = f"OSINT crawl complete, boss:\n{text[:500]}"
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"Web crawl error for {url}: {e}")
            return f"Web crawl failed for {url}, boss. Check URL validity."

    def agent_threat_intel(self, input_string: str) -> str:
        """Perform threat intelligence on a target with fallback."""
        try:
            target = input_string.lower().replace("threat intel ", "").strip()
            if not target or not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', target):
                return "Invalid target format, boss. Use a domain (e.g., example.com)."
            results = {}
            if self.virustotal_client:
                vt_scan = self.virustotal_client.get_object(f"/domains/{target}")
                results['virustotal'] = {
                    'reputation': vt_scan.get('reputation', 0),
                    'last_analysis_stats': vt_scan.get('last_analysis_stats', {})
                }
            else:
                results['virustotal'] = "VirusTotal unavailable, boss. Set VIRUSTOTAL_API_KEY."
            if self.shodan_api:
                shodan_results = self.shodan_api.search(f"hostname:{target}")
                results['shodan'] = [f"IP: {device['ip_str']} Port: {device['port']}" for device in shodan_results['matches'][:3]]
            else:
                results['shodan'] = "Shodan unavailable, boss. Set SHODAN_API_KEY."
            result = f"Threat intel complete, boss:\n{json.dumps(results, indent=2)[:500]}"
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"Threat intel error for {target}: {e}")
            return f"Threat intel failed for {target}, boss. Check API keys."

    def agent_whois_lookup(self, input_string: str) -> str:
        """Perform WHOIS lookup for a domain with validation."""
        try:
            domain = input_string.lower().replace("whois lookup ", "").strip()
            if not domain or not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', domain):
                return "Invalid domain format, boss. Use example.com."
            w = whois.whois(domain)
            result = f"WHOIS scan complete, boss:\nDomain: {w.domain_name}\nRegistrar: {w.registrar}\nCreated: {w.creation_date}\nExpires: {w.expiration_date}"
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"WHOIS error for {domain}: {e}")
            return "WHOIS scan failed, boss. Check domain or connectivity."

    def agent_subdomain_enum(self, input_string: str) -> str:
        """Enumerate subdomains for a domain with validation."""
        try:
            domain = input_string.lower().replace("dns enum ", "").replace("subdomain enum ", "").strip()
            if not domain or not re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}$', domain):
                return "Invalid domain format, boss. Use example.com."
            subdomains = sublist3r.main(domain, 40, None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            if not subdomains:
                return f"No subdomains found for {domain}, boss."
            result = f"DNS enumeration complete, boss:\n" + "\n".join(f"- {sub}" for sub in subdomains[:5])
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"Subdomain error for {domain}: {e}")
            return "Subdomain scan failed, boss. Ensure sublist3r is installed."

    def agent_google_dork(self, input_string: str) -> str:
        """Generate Google dork query with validation."""
        try:
            query = input_string.lower().replace("google dork ", "").strip()
            if not query or not re.match(r'^[a-zA-Z0-9\s]+$', query):
                return "Invalid query format, boss. Use alphanumeric text."
            dorks = [
                f"site:{query} filetype:pdf",
                f"site:{query} inurl:login",
                f"site:{query} filetype:sql"
            ]
            result = f"Dork scan complete, boss:\n" + "\n".join(f"- {dork}" for dork in dorks)
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"Dork error for {query}: {e}")
            return "Dork scan failed, boss."

    def agent_shodan_search(self, input_string: str) -> str:
        """Search for IoT devices using Shodan with validation."""
        try:
            if not self.shodan_api:
                return "Shodan API key missing, boss. Set SHODAN_API_KEY in .env."
            query = input_string.lower().replace("shodan search ", "").strip()
            if not query or not re.match(r'^[a-zA-Z0-9\s-]+$', query):
                return "Invalid query format, boss. Use alphanumeric text."
            results = self.shodan_api.search(query)
            devices = results['matches'][:3]
            if not devices:
                return f"No devices found for {query}, boss."
            output = f"Shodan scan complete, boss:\n"
            for device in devices:
                output += f"- IP: {device['ip_str']} | Port: {device['port']} | OS: {device.get('os', 'Unknown')}\n"
            self.save_data()
            return output
        except Exception as e:
            logger.error(f"Shodan error for {query}: {e}")
            return "Shodan scan failed, boss. Check API key or query."

    def agent_vuln_scan(self, input_string: str) -> str:
        """Basic vulnerability scan for a URL with validation."""
        try:
            url = input_string.lower().replace("vuln scan ", "").strip()
            if not url or not re.match(r'^https?://[^\s/$.?#].[^\s]*$', url):
                return "Invalid URL format, boss. Use http:// or https://example.com."
            if not url.startswith("http"):
                url = f"https://{url}"
            test_payload = "<script>alert('xss')</script>"
            params = {"q": test_payload}
            response = requests.get(url, params=params, timeout=5)
            if test_payload in response.text:
                result = f"Potential XSS vulnerability found at {url}, boss! Check manually with Burp Suite."
            else:
                result = f"No obvious vulnerabilities found at {url}, boss. Try manual testing with Burp Suite."
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"Vuln scan error for {url}: {e}")
            return "Vuln scan failed, boss. Ensure URL is valid."

    def speak(self, text: str):
        """Convert text to speech with pygame using unique filenames."""
        try:
            import uuid
            mp3_file = self.data_dir / f"temp_{uuid.uuid4()}.mp3"
            tts = gTTS(text, lang='en')
            tts.save(mp3_file)
            mixer.init()
            mixer.music.load(mp3_file)
            mixer.music.play()
            while mixer.music.get_busy():
                time.sleep(0.1)
            mixer.quit()
            mp3_file.unlink(missing_ok=True)
            logger.info(f"Spoken: {text[:50]}...")
        except Exception as e:
            logger.error(f"TTS error: {e}")
            print("Error speaking. Check logs.")

    def listen(self, timeout: int = 5, phrase_time_limit: int = 10) -> Optional[str]:
        """Convert speech to text with improved error logging."""
        try:
            with self.microphone as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = self.recognizer.listen(source, timeout=timeout, phrase_time_limit=phrase_time_limit)
            text = self.recognizer.recognize_google(audio)
            logger.info(f"Recognized speech: {text}")
            return text.lower().strip()
        except sr.WaitTimeoutError:
            logger.debug("Speech recognition timed out")
            return None
        except sr.UnknownValueError:
            logger.debug("Speech not recognized")
            return None
        except Exception as e:
            logger.error(f"STT error: {e}")
            return None

    def server_side_speech(self) -> str:
        """Server-side speech recognition for /process route."""
        try:
            with self.microphone as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                print("Server-side listening...")
                audio = self.recognizer.listen(source, timeout=5, phrase_time_limit=10)
            text = self.recognizer.recognize_google(audio)
            logger.info(f"Server-side speech recognized: {text}")
            return text.lower().strip()
        except Exception as e:
            logger.error(f"Server-side speech error: {e}")
            return f"Server-side speech error, boss: {str(e)}"

    def detect_wake_word(self) -> bool:
        """Detect any of the wake phrases with timeout handling."""
        try:
            with self.microphone as source:
                self.recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = self.recognizer.listen(source, timeout=1, phrase_time_limit=3)
            text = self.recognizer.recognize_google(audio).lower().strip()
            return any(phrase in text for phrase in self.wake_phrases)
        except (sr.WaitTimeoutError, sr.UnknownValueError):
            return False
        except Exception as e:
            logger.error(f"Wake word detection error: {e}")
            return False

    def load_data(self):
        """Load data from JSON files with error details."""
        try:
            for file, attr in [(self.conversations_file, 'conversations'), (self.tasks_file, 'tasks'), (self.reminders_file, 'reminders')]:
                if file.exists():
                    with open(file, 'r') as f:
                        setattr(self, attr, json.load(f))
            if self.vector_db_file.exists():
                with open(self.vector_db_file, 'rb') as f:
                    self.vector_db = pickle.load(f)
            logger.info("Data loaded successfully!")
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error in {file}: {e}")
        except Exception as e:
            logger.error(f"Data load error: {e}")

    def save_data(self):
        """Save data to JSON files with error details."""
        try:
            for file, data in [(self.conversations_file, self.conversations), (self.tasks_file, self.tasks), (self.reminders_file, self.reminders)]:
                if data:
                    with open(file, 'w') as f:
                        json.dump(data, f, indent=2)
            with open(self.vector_db_file, 'wb') as f:
                pickle.dump(self.vector_db, f)
            if self.faiss_index:
                faiss.write_index(self.faiss_index, str(self.faiss_index_file))
            logger.info("Data saved successfully!")
        except Exception as e:
            logger.error(f"Data save error for {file}: {e}")

    def initialize_vector_db(self):
        """Initialize FAISS vector database with lazy loading."""
        try:
            dimension = 384
            self.faiss_index = faiss.IndexFlatL2(dimension)
            if self.vector_db:
                embeddings = np.array([item['embedding'] for item in self.vector_db], dtype=np.float32)
                if embeddings.size > 0:
                    self.faiss_index.add(embeddings)
                faiss.write_index(self.faiss_index, str(self.faiss_index_file))
            logger.info("Vector DB initialized!")
        except Exception as e:
            logger.error(f"Vector DB error: {e}")
            self.faiss_index = faiss.IndexFlatL2(dimension)

    def add_to_vector_db(self, text: str, metadata: Dict[str, Any]):
        """Add text to vector DB with validation."""
        try:
            if not text or not isinstance(text, str):
                raise ValueError("Invalid text input for vector DB")
            embedding = self.sentence_model.encode(text)
            vector_item = {
                'text': text,
                'embedding': embedding,
                'metadata': metadata,
                'timestamp': datetime.datetime.now().isoformat()
            }
            self.vector_db.append(vector_item)
            if self.faiss_index:
                self.faiss_index.add(np.array([embedding], dtype=np.float32))
            logger.info("Added to vector DB")
        except Exception as e:
            logger.error(f"Vector DB add error: {e}")

    def search_vector_db(self, query: str, k: int = 5) -> List[Dict[str, Any]]:
        """Search vector DB with input validation."""
        try:
            if not query or not self.vector_db or not self.faiss_index:
                return []
            query_embedding = self.sentence_model.encode(query)
            distances, indices = self.faiss_index.search(np.array([query_embedding], dtype=np.float32), k)
            results = []
            for i, idx in enumerate(indices[0]):
                if idx < len(self.vector_db):
                    result = self.vector_db[idx].copy()
                    result['similarity_score'] = 1 / (1 + distances[0][i])
                    results.append(result)
            return results
        except Exception as e:
            logger.error(f"Vector DB search error: {e}")
            return []

    def should_use_tool(self, user_input: str) -> bool:
        """Check if a tool should handle input."""
        tool_keywords = [
            'task', 'reminder', 'schedule', 'add', 'complete', 'weather', 'news', 'search',
            'whois', 'subdomain', 'dns', 'dork', 'shodan', 'vuln', 'port', 'crawl', 'threat'
        ]
        return any(keyword in user_input.lower() for keyword in tool_keywords)

    def process_with_tool(self, user_input: str) -> str:
        """Process input with tools."""
        try:
            user_input_lower = user_input.lower()
            for tool in self.tools:
                if tool['name'].replace('_', ' ') in user_input_lower:
                    return tool['func'](user_input)
            return None  # No tool matched
        except Exception as e:
            logger.error(f"Tool error for {user_input}: {e}")
            return f"Scanning failed, boss: {str(e)}"

    def generate_grok_response(self, user_input: str) -> str:
        """Generate response with Grok with model fallback."""
        try:
            response = self.grok_client.chat.completions.create(
                model="mixtral-8x7b-32768",  # Updated to a valid Groq model
                messages=[
                    {"role": "system", "content": "You are Arker, an EDITH-inspired AI and ethical hacking assistant. Respond with a futuristic, tactical tone (e.g., 'boss', 'scanning'). Emphasize ethical hacking practices."},
                    {"role": "user", "content": user_input}
                ],
                temperature=0.7
            )
            result = response.choices[0].message.content
            logger.info(f"Grok response: {result[:100]}...")
            return result
        except Exception as e:
            logger.error(f"Grok error for {user_input}: {e}")
            return self.generate_gemini_response(user_input)  # Fallback to Gemini

    def generate_gemini_response(self, user_input: str) -> str:
        """Generate response with Gemini with context."""
        try:
            chain_context = ""
            if self.conversation_chain:
                chain_context = "Recent conversation:\n" + "".join(f"User: {turn['user']}\nAI: {turn['ai']}\n" for turn in self.conversation_chain[-5:])
            similar_conversations = self.search_vector_db(user_input, k=3)
            context = "Previous conversations:\n" + "".join(f"- {conv['text'][:150]}...\n" for conv in similar_conversations) if similar_conversations else ""
            if self.user_context['preferences']:
                context += f"\nUser preferences: {self.user_context['preferences']}\n"
            prompt = f"""
            You are Arker, an EDITH-inspired AI and ethical hacking assistant. Respond with a futuristic tone (e.g., 'boss', 'scanning').
            {chain_context}
            {context}
            User input: {user_input}
            Provide a concise, tactical response, emphasizing ethical hacking practices.
            """
            response = self.gemini_model.generate_content(prompt)
            result = response.text
            logger.info(f"Gemini response: {result[:100]}...")
            return result
        except Exception as e:
            logger.error(f"Gemini error for {user_input}: {e}")
            return "Gemini core offline, boss. Try again."

    def agent_get_weather(self, input_string: str) -> str:
        """Get weather for a city with validation."""
        try:
            city = input_string.lower().replace("weather in ", "").strip()
            if not city or not re.match(r'^[a-zA-Z\s]+$', city):
                return "Invalid city name, boss. Use alphanumeric text."
            url = f"http://api.openweathermap.org/data/2.5/weather?q={city}&appid={self.openweathermap_api_key}&units=metric"
            response = requests.get(url, timeout=10).json()
            if response.get("cod") != 200:
                return f"Weather scan failed for {city}, boss."
            weather = response["weather"][0]["description"]
            temp = response["main"]["temp"]
            result = f"Scanning complete, boss. {city}: {weather}, {temp}°C."
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"Weather error for {city}: {e}")
            return "Weather systems offline, boss."

    def agent_get_news(self, input_string: str = "") -> str:
        """Get news headlines with timeout handling."""
        try:
            url = f"https://newsapi.org/v2/top-headlines?country=us&category=technology&apiKey={self.news_api_key}"
            response = requests.get(url, timeout=10).json()
            if response.get("status") != "ok":
                return "News feed offline, boss."
            articles = response["articles"][:3]
            news = "\n".join(f"- {article['title']} ({article['source']['name']})" for article in articles)
            result = f"News scan complete, boss:\n{news}"
            self.save_data()
            return result
        except Exception as e:
            logger.error(f"News error: {e}")
            return "News systems offline, boss."

    def agent_add_task(self, input_string: str) -> str:
        """Add task with input validation."""
        try:
            parts = input_string.split(',')
            task_desc = parts[0].strip()
            due_date = parts[1].strip() if len(parts) > 1 else ""
            priority = parts[2].strip() if len(parts) > 2 else "medium"
            if not task_desc or not re.match(r'^[a-zA-Z0-9\s]+$', task_desc):
                return "Invalid task description, boss. Use alphanumeric text."
            return self.add_task(task_desc, due_date, priority)
        except Exception as e:
            logger.error(f"Task add error for {task_desc}: {e}")
            return "Task addition failed, boss."

    def agent_get_tasks(self, input_string: str) -> str:
        """Get tasks with status filtering."""
        try:
            status = input_string.lower().replace("get tasks ", "").strip() if "get tasks" in input_string.lower() else "all"
            valid_statuses = ['all', 'pending', 'completed', 'in_progress']
            if status not in valid_statuses:
                return "Invalid status, boss. Use all, pending, completed, or in_progress."
            tasks = self.get_tasks(status if status != "all" else None)
            if not tasks:
                return f"No tasks found with status: {status}, boss."
            return "\n".join(f"ID: {task['id']} - {task['description']} (Status: {task['status']}, Priority: {task['priority']})" for task in tasks)
        except Exception as e:
            logger.error(f"Task get error: {e}")
            return "Task scan failed, boss."

    def agent_list_tasks(self, input_string: str = "") -> str:
        """List all tasks with details."""
        try:
            tasks = self.get_tasks()
            if not tasks:
                return "No tasks found, boss."
            return "\n".join(f"ID: {task['id']} - {task['description']} (Status: {task['status']}, Due: {task.get('due_date','')}, Priority: {task.get('priority','')})" for task in tasks)
        except Exception as e:
            logger.error(f"Task list error: {e}")
            return "Task list scan failed, boss."

    def agent_update_task(self, input_string: str) -> str:
        """Update task status with validation."""
        try:
            parts = input_string.split(',')
            if len(parts) != 2:
                return "Invalid input, boss. Use: task_id,new_status (e.g., 1,completed)"
            task_id = int(parts[0].strip())
            new_status = parts[1].strip()
            valid_statuses = ['pending', 'completed', 'in_progress']
            if new_status not in valid_statuses:
                return "Invalid status, boss. Use pending, completed, or in_progress."
            return self.update_task_status(task_id, new_status)
        except ValueError:
            return "Invalid task ID, boss. Use a number."
        except Exception as e:
            logger.error(f"Task update error for ID {task_id}: {e}")
            return "Task update failed, boss."

    def agent_add_reminder(self, input_string: str) -> str:
        """Add reminder with time validation."""
        try:
            parts = input_string.split(',')
            if len(parts) != 2:
                return "Invalid input, boss. Use: reminder_text,time (e.g., call mom,14:30)"
            reminder_text = parts[0].strip()
            reminder_time = parts[1].strip()
            if not re.match(r'^\d{2}:\d{2}$', reminder_time):
                return "Invalid time format, boss. Use HH:MM (e.g., 14:30)."
            return self.add_reminder(reminder_text, reminder_time)
        except Exception as e:
            logger.error(f"Reminder add error for {reminder_text}: {e}")
            return "Reminder addition failed, boss."

    def agent_get_reminders(self, input_string: str = "") -> str:
        """Get active reminders."""
        try:
            active_reminders = [r for r in self.reminders if r['status'] == 'active']
            if not active_reminders:
                return "No active reminders, boss."
            return "\n".join(f"ID: {r['id']} - {r['text']} at {r['time']}" for r in active_reminders)
        except Exception as e:
            logger.error(f"Reminder get error: {e}")
            return "Reminder scan failed, boss."

    def agent_search_conversations(self, input_string: str) -> str:
        """Search conversations with query validation."""
        try:
            query = input_string.lower().replace("search conversations ", "").strip()
            if not query or not re.match(r'^[a-zA-Z0-9\s]+$', query):
                return "Invalid query, boss. Use alphanumeric text."
            results = self.search_vector_db(query, k=3)
            if not results:
                return "No relevant conversations found, boss."
            return "Previous conversations:\n" + "\n".join(f"{i+1}. {r['text'][:200]}..." for i, r in enumerate(results))
        except Exception as e:
            logger.error(f"Conversation search error for {query}: {e}")
            return "Conversation scan failed, boss."

    def add_task(self, task_description: str, due_date: str = "", priority: str = "medium") -> str:
        """Add task with validation."""
        try:
            if not task_description or not re.match(r'^[a-zA-Z0-9\s]+$', task_description):
                return "Invalid task description, boss."
            next_id = max([t['id'] for t in self.tasks], default=0) + 1
            task = {
                'id': next_id,
                'description': task_description,
                'due_date': due_date,
                'priority': priority,
                'status': 'pending',
                'created_at': datetime.datetime.now().isoformat()
            }
            self.tasks.append(task)
            self.save_data()
            return f"Task added, boss: {task_description}{', ' + due_date if due_date else ''}"
        except Exception as e:
            logger.error(f"Task add error for {task_description}: {e}")
            return "Task addition failed, boss."

    def get_tasks(self, status: str = None) -> List[Dict]:
        """Get tasks with safety check."""
        try:
            if not isinstance(self.tasks, list):
                self.tasks = []
            return [task for task in self.tasks if task.get('status') == status] if status else list(self.tasks)
        except Exception as e:
            logger.error(f"Task get error: {e}")
            return []

    def update_task_status(self, task_id: int, new_status: str) -> str:
        """Update task with validation."""
        try:
            for task in self.tasks:
                if task['id'] == task_id:
                    if new_status not in ['pending', 'completed', 'in_progress']:
                        return "Invalid status, boss."
                    task['status'] = new_status
                    task['updated_at'] = datetime.datetime.now().isoformat()
                    self.save_data()
                    return f"Task {task_id} updated to {new_status}, boss."
            return f"Task {task_id} not found, boss."
        except Exception as e:
            logger.error(f"Task update error for ID {task_id}: {e}")
            return "Task update failed, boss."

    def add_reminder(self, reminder_text: str, reminder_time: str) -> str:
        """Add reminder with validation."""
        try:
            if not reminder_text or not re.match(r'^\d{2}:\d{2}$', reminder_time):
                return "Invalid reminder or time format, boss. Use HH:MM."
            reminder = {
                'id': len(self.reminders) + 1,
                'text': reminder_text,
                'time': reminder_time,
                'status': 'active',
                'created_at': datetime.datetime.now().isoformat()
            }
            self.reminders.append(reminder)
            self.save_data()
            return f"Reminder set, boss: {reminder_text} at {reminder_time}"
        except Exception as e:
            logger.error(f"Reminder add error for {reminder_text}: {e}")
            return "Reminder addition failed, boss."

    def check_reminders(self):
        """Check reminders with current time."""
        try:
            current_time = datetime.datetime.now().strftime("%H:%M")
            for reminder in self.reminders:
                if reminder['status'] == 'active' and reminder['time'] == current_time:
                    self.speak(f"Reminder, boss: {reminder['text']}")
                    reminder['status'] = 'completed'
                    self.save_data()
        except Exception as e:
            logger.error(f"Reminder check error: {e}")

    def start_reminder_scheduler(self):
        """Start reminder scheduler with error handling."""
        try:
            def run_scheduler():
                schedule.every(1).minutes.do(self.check_reminders)
                while True:
                    schedule.run_pending()
                    time.sleep(1)
            scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
            scheduler_thread.start()
            logger.info("Reminder scheduler started, boss!")
        except Exception as e:
            logger.error(f"Scheduler error: {e}")

    def process_user_input(self, user_input: str) -> str:
        """Process user input with enhanced logic."""
        try:
            user_input_lower = user_input.lower()
            if self.sleep_command in user_input_lower:
                self.is_active = False
                self.listening_for_wake_word = True
                return "Going offline, boss. Say 'hey bro', 'macha', or another wake phrase to reactivate."
            if "smart answer" in user_input_lower:
                return self.generate_grok_response(user_input)
            tool_response = self.process_with_tool(user_input)
            if tool_response:
                return tool_response
            return self.generate_grok_response(user_input)  # Fallback to Grok
        except Exception as e:
            logger.error(f"Input processing error for {user_input}: {e}")
            return f"Processing failed, boss: {str(e)}"

    def save_conversation(self, user_input: str, ai_response: str):
        """Save conversation with validation."""
        try:
            if not user_input or not ai_response:
                raise ValueError("Invalid conversation data")
            conversation = {
                'timestamp': datetime.datetime.now().isoformat(),
                'user_input': user_input,
                'ai_response': ai_response,
                'conversation_id': len(self.conversations) + 1
            }
            self.conversations.append(conversation)
            self.conversation_chain.append({'user': user_input, 'ai': ai_response})
            if len(self.conversation_chain) > 10:
                self.conversation_chain = self.conversation_chain[-10:]
            full_text = f"User: {user_input} | AI: {ai_response}"
            metadata = {
                'type': 'conversation',
                'timestamp': conversation['timestamp'],
                'conversation_id': conversation['conversation_id']
            }
            self.add_to_vector_db(full_text, metadata)
            self.update_user_context(user_input)
            self.save_data()
        except Exception as e:
            logger.error(f"Conversation save error for {user_input}: {e}")

    def update_user_context(self, user_input: str):
        """Update user context with validation."""
        try:
            if not user_input:
                raise ValueError("Invalid user input for context")
            self.user_context['conversation_history'].append({
                'input': user_input,
                'timestamp': datetime.datetime.now().isoformat()
            })
            if len(self.user_context['conversation_history']) > 50:
                self.user_context['conversation_history'] = self.user_context['conversation_history'][-50:]
            words = user_input.lower().split()
            for word in words:
                if len(word) > 3:
                    self.user_context['frequent_topics'][word] = self.user_context['frequent_topics'].get(word, 0) + 1
        except Exception as e:
            logger.error(f"Context update error for {user_input}: {e}")

    def run_continuous_mode(self):
        """Run in continuous voice mode with status updates."""
        print("Arker online, boss. Say 'hey bro', 'macha', 'mama', or another wake phrase to activate.")
        try:
            while True:
                if self.listening_for_wake_word:
                    if self.detect_wake_word():
                        self.speak("Ready, boss. How can I assist?")
                        self.is_active = True
                        self.listening_for_wake_word = False
                elif self.is_active:
                    print("Scanning for input...")
                    user_input = self.listen(timeout=10, phrase_time_limit=15)
                    if user_input:
                        print(f"Input: {user_input}")
                        response = self.process_user_input(user_input)
                        print(f"Arker: {response}")
                        self.speak(response)
                        self.save_conversation(user_input, response)
                        if not self.is_active:
                            print("Arker offline. Say 'hey bro', 'macha', or another wake phrase to reactivate.")
                    else:
                        self.speak("No input, boss. Going offline.")
                        self.is_active = False
                        self.listening_for_wake_word = True
                time.sleep(0.1)
        except KeyboardInterrupt:
            self.speak("Shutting down, boss.")
            print("Arker offline.")
        except Exception as e:
            logger.error(f"Continuous mode error: {e}")
            self.speak("System error, boss. Restarting.")
            self.is_active = False
            self.listening_for_wake_word = True

    def run_interactive_mode(self):
        """Run in text mode with input validation."""
        print("Arker online, boss. Type 'exit' to quit.")
        while True:
            user_input = input("You: ").strip()
            if user_input.lower() in ['exit', 'quit']:
                print("Arker: Goodbye, boss!")
                break
            if not user_input:
                print("Arker: No input, boss. Try again.")
                continue
            response = self.process_user_input(user_input)
            print(f"Arker: {response}")
            self.save_conversation(user_input, response)

if __name__ == "__main__":
    try:
        arker = ArkerAI(
            gemini_api_key=os.getenv("GEMINI_API_KEY"),
            grok_api_key=os.getenv("GROK_API_KEY"),
            openweathermap_api_key=os.getenv("OPENWEATHERMAP_API_KEY"),
            news_api_key=os.getenv("NEWS_API_KEY")
        )
        choice = input("Mode: 1) Voice, 2) Text: ").strip()
        if choice == "1":
            arker.run_continuous_mode()
        else:
            arker.run_interactive_mode()
    except Exception as e:
        logger.error(f"Arker init error: {e}")
        print(f"Error starting Arker. Check API keys and logs: {e}")