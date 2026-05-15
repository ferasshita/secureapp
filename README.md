# secureapp

## Installation

1. Clone the repository and move into it.
2. Create and activate a virtual environment.
3. Install dependencies from `requirements.txt`.
4. Apply database migrations.
5. Start the development server.

```bash
git clone https://github.com/ferasshita/secureapp.git
cd secureapp

python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```
