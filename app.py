# Standard Library Imports
import os
import sys
import json
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

# Flask & Related Modules
from flask import Flask, render_template, request, redirect, session, url_for, jsonify
from flask_cors import CORS, cross_origin
from flask_session import Session
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect, generate_csrf
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt, create_refresh_token
)

# Security & Utilities
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv

# Logging & Exception Handling
from playground.logger import logging
from playground.exception import CustomException
from playground.models import db, Report

# AI & LangChain Modules
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain.memory import ConversationBufferWindowMemory
from langchain.prompts import PromptTemplate, ChatPromptTemplate
from langchain.chains.question_answering import load_qa_chain
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.chat_message_histories import ChatMessageHistory
from langchain_community.vectorstores import Chroma, FAISS
from langchain_aws import ChatBedrockConverse

#------- function --------
from playground.utils import extract_text_from_msg, process_image_1, extract_tables_from_docx, extract_text_from_docx, extract_text_from_pdf, process_doc, extract_key_value_pairs, generate_session_id, get_w2_data
#------- conversational_chain --------
from playground.utils import conversational_chain_revised, conversational_chain_revised_json, conversational_chain, chat_chain, conversational_chain_student, process_image_pdf_3, process_image_pdf_4, structure_checkbox_response, structure_student_verification, savings_chain, tax_credits_chain, withholding_chain, get_conversational_chain, memory
#------- Prompt --------
from playground.utils import prompt_template, template, summary_input, outline_input, action_items_input, red_flags_input, outline_money_input, write_questions_input, explain_glossary_input
from playground.utils import summary_input_policy, outline_input_policy, intended_audience_input_policy, action_items_input_policy, prompt_template_policy
from playground.utils import json_output, checkbox_output
from playground.utils import json_output_medical, personal_output_medical, student_detail, student_verification, student_sign_verification, student_sign_verification_structurize, extract_checkboxes, structure_student_response_prompt



load_dotenv()

OpenAI = os.getenv('OPENAI_API_KEY')

embeddings = OpenAIEmbeddings()
vectordb = FAISS.load_local("faiss_index", embeddings, allow_dangerous_deserialization=True)

app = Flask(__name__)
app.url_map.strict_slashes = True
app.secret_key = os.getenv("SECRET_KEY")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
Session(app)
csrf = CSRFProtect(app)

db.init_app(app)

# JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')  # Change this to a secure key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
jwt = JWTManager(app)

CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:5173", "http://127.0.0.1:5000", "http://api-taxanalyser.fintegrationai.com", "https://api-taxanalyser.fintegrationai.com", "https://taxanalyser.fintegrationai.com", "http://taxanalyser.fintegrationai.com"],  # Add your frontend URL
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "expose_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

chat_history = ChatMessageHistory()
llm=ChatOpenAI(model="gpt-4o")

persist_directory = "DB"
user_memory=ConversationBufferWindowMemory(k=25, memory_key="chat_history", input_key="question")

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username == "MobileFirst":
            if password == "BuildKarenge":
                session['user_id'] = username
                return redirect(url_for("homepage"))
            else:
                return "Incorrect Password"
        else:
            return "Incorrect Username"

    return render_template("login.html", form=form)

@app.route("/", methods=["GET"])
def index():
    # print(app.url_map)
    return render_template("index.html")

@app.route("/legal", methods=["GET"])
@app.route("/legal/", methods=["GET"])
@login_required
def index_legal():
    # return "This is the legal page"
    return render_template("index_legal.html")

@app.route("/policy", methods=["GET"])
@app.route("/policy/", methods=["GET"])
@login_required
def index_policy():
    return render_template("index_policy.html")

@app.route("/extraction", methods=["GET"])
@login_required
def index_extraction():
    return render_template("index_extraction.html")

@app.route("/medical", methods=["GET"])
@login_required
def index_medical():
    return render_template("index_medical.html")

@app.route("/textAnalyser",method=["GET"])
@login_required
def index_textAnalyser():
    return render_template("index_textAnalyser.html")

@app.route('/product')
def product_page():
    return render_template("product.html")

@app.route('/about')
def about():
    return render_template('about.html')

@app.route("/result", methods=["GET"])
@login_required
def result():
    return render_template("result.html")

@app.route("/upload", methods=["GET", "POST"])
@login_required
def homepage():
    if request.method == "POST":
        document = request.files['fileInput']
        project = request.form['selectedProject']
        # email = request.form.get("emailID")
        # session["user_email"] = email
        # userid = email.split("@")[0].replace(".", "_")
        # mailhost = email.split("@")[1].replace(".", "_")
        # session['user_id'] = userid + mailhost
        session_id = generate_session_id(document)
        session['user_id'] = session_id
        print("Generated Session ID:", session['user_id'])  # For debugging purposes

        filename = secure_filename(document.filename)
        new_path = os.path.join("uploads", filename)
        file_ext = os.path.splitext(filename)[1].lower()
        
        session_keys = ['format_extraction', 'text', 'texts', 'json_extraction', 'checkbox_response']
        
        # Clear the session data if needed
        for key in session_keys:
            print("Cleared session : ", key)
            session.pop(key, None)
 
        if file_ext == '.msg':
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_msg_file:
                    document.save(temp_msg_file.name)
                    msg_text = extract_text_from_msg(temp_msg_file.name)
                    if msg_text:
                        session['text'] = f"Message extracted from .msg file:\n\n{msg_text}"
                    else:
                        session['text'] = "Failed to extract message from .msg file."

                    text_splitter = RecursiveCharacterTextSplitter(chunk_size=10000, chunk_overlap=200)
                    if isinstance(msg_text, list):
                        msg_text = ' '.join(msg_text)

                    texts = text_splitter.split_text(msg_text)
                    session['texts'] = texts
                    vectordb = Chroma.from_texts(texts=texts,embedding=embeddings,collection_name=session['user_id'],persist_directory=persist_directory)
                    vectordb.persist()
                    vectordb = None

                    if project == "legal":
                        return redirect("analysis_legal")
                    elif project == "policy":
                        return redirect("analysis_policy")
                    elif project == "extraction":
                        return redirect("analysis_extraction")
                    elif project == "medical":
                        return redirect("analysis_medical")

            except Exception as e:
                print(f"Error processing .msg file: {e}")
                return str(e), 500

        elif file_ext in ['.doc', '.docx']:
            document.save(new_path)
            text = extract_text_from_docx(new_path)
            session['text'] = f"This is the context you have to work with. Here is the context: {text}"

            text_splitter = RecursiveCharacterTextSplitter(chunk_size=10000, chunk_overlap=200)
            if isinstance(text, list):
                text = ' '.join(text)
            texts = text_splitter.split_text(text)
            session['texts'] = texts
            vectordb = Chroma.from_texts(texts=texts,embedding=embeddings,collection_name=session['user_id'],persist_directory=persist_directory)
            vectordb.persist()
            vectordb = None

            if project == "legal":
                return redirect("analysis_legal")
            elif project == "policy":
                return redirect("analysis_policy")
            elif project == "extraction":
                return redirect("analysis_extraction")
            elif project == "medical":
                return redirect("analysis_medical")

        elif file_ext in ['.png', '.jpg', '.jpeg']:
            upload_folder = "uploads"
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            image_path = os.path.join(upload_folder, filename)

            try:
                if hasattr(document, 'save'):
                    document.save(image_path)  # Save uploaded file
                else:
                    raise ValueError("Uploaded document is not a file-like object.")
                
                text = process_image_1(image_path)

                if not text:
                    raise ValueError("Text extraction failed or returned empty content.")

                session['text'] = f"This is the context you have to work with. Here is the context: {text}"

                text_splitter = RecursiveCharacterTextSplitter(chunk_size=10000, chunk_overlap=200)
                if isinstance(text, list):
                    text = ' '.join(text)
                texts = text_splitter.split_text(text)
                session['texts'] = texts
                vectordb = Chroma.from_texts(texts=texts,embedding=embeddings,collection_name=session['user_id'],persist_directory=persist_directory)
                vectordb.persist()
                vectordb = None

                if project == "legal":
                    return redirect("analysis_legal")
                elif project == "policy":
                    return redirect("analysis_policy")
                elif project == "extraction":
                    return redirect("analysis_extraction")
                elif project == "medical":
                    return redirect("analysis_medical")

            except Exception as e:
                print(f"Error processing image file: {e}")
                return str(e), 500

        else:
            # Save the uploaded file
            upload_folder = "uploads"
            if not os.path.exists(upload_folder):
                os.makedirs(upload_folder)
            pdf_path = os.path.join(upload_folder, document.filename)
            session['path'] = pdf_path
            document.save(pdf_path)

        try:
            text, count, null_count = extract_text_from_pdf(pdf_path)

            if (text == None) or (int(null_count) / int(count) >= 0.80):
                text = process_doc(pdf_path)
                # tabular_data =
                session['text'] = f"""
                This is the context you have to work with. Ensure that all responses refer back to this context, as it is very important that you generate 100% accurate responses. Here is the context: {text}
                """

                text_splitter = RecursiveCharacterTextSplitter(chunk_size=10000, chunk_overlap=200)
                if isinstance(text, list):
                    text = ' '.join(text)
                texts = text_splitter.split_text(text)
                session['texts'] = texts
                
                print(session['texts'])
                
                vectordb = Chroma.from_texts(texts=texts,embedding=embeddings,collection_name=session['user_id'],persist_directory=persist_directory)
                vectordb.persist()
                vectordb = None

                if project == "legal":
                    return redirect("analysis_legal")
                elif project == "policy":
                    return redirect("analysis_policy")
                elif project == "extraction":
                    return redirect("analysis_extraction")
                elif project == "medical":
                    return redirect("analysis_medical")

            # print("Response generate from pdf")
            session['text'] = f"""
            This is the context you have to work with. Ensure that all responses refer back to this context, as it is very important that you generate 100% accurate responses. Here is the context: {text}
            """

            text_splitter = RecursiveCharacterTextSplitter(chunk_size=10000, chunk_overlap=200)
            if isinstance(text, list):
                text = ' '.join(text)
            texts = text_splitter.split_text(text)
            session['texts'] = texts
            vectordb = Chroma.from_texts(texts=texts,embedding=embeddings,collection_name=session['user_id'],persist_directory=persist_directory)
            vectordb.persist()
            vectordb = None

            if project == "legal":
                return redirect("analysis_legal")
            elif project == "policy":
                return redirect("analysis_policy")
            elif project == "extraction":
                return redirect("analysis_extraction")
            elif project == "medical":
                return redirect("analysis_medical")

        except Exception as e:
            text = process_doc(pdf_path)
            print(f"pdf data extracted using openai : {text}")
            session['text'] = f"""
            This is the context you have to work with. Ensure that all responses refer back to this context, as it is very important that you generate 100% accurate responses. Here is the context: {text}
            """

            text_splitter = RecursiveCharacterTextSplitter(chunk_size=10000, chunk_overlap=200)
            if isinstance(text, list):
                text = ' '.join(text)
            texts = text_splitter.split_text(text)
            session['texts'] = texts
            vectordb = Chroma.from_texts(texts=texts,embedding=embeddings,collection_name=session['user_id'],persist_directory=persist_directory)
            vectordb.persist()
            vectordb = None

            if project == "legal":
                return redirect("analysis_legal")
            elif project == "policy":
                return redirect("analysis_policy")
            elif project == "extraction":
                return redirect("analysis_extraction")
            elif project == "medical":
                return redirect("analysis_medical")

    else:
        return render_template("upload.html")


#---------------------------------------- Legal ---------------------------------------


@app.route("/analysis_legal", methods=["GET","POST"])
@login_required
def analysis_legal():
    if request.method == "POST":
        if len(user_memory.load_memory_variables({})["chat_history"].split("\n")):
            question = request.form['msg']
            persist_directory="DB"
            vectordb = Chroma(persist_directory=persist_directory,embedding_function=embeddings, collection_name=session['user_id'])
            retriever = vectordb.as_retriever(search_type="mmr", search_kwargs={"k":1})
            docs = retriever.get_relevant_documents(question,max_tokens=1024)
            prompt = PromptTemplate(template = prompt_template, input_variables = ["context", "question", "chat_history"],max_tokens=1024)
            chain = load_qa_chain(llm, chain_type="stuff", prompt=prompt, memory=user_memory)
            response = chain.invoke(
                {"input_documents":docs, "question": question}
                , return_only_outputs=True)
            return str(response['output_text'])
        else:
            return "You have exceeded your maximum chat limit"

    summary_response=""
    clauses_response=""
    items_response = ""
    flags_response = ""
    money_response = ""
    questions_response = ""
    glossary_response = ""

    # Function 1: Generate summary
    # summary_response = session['summary_response']
    # print(summary_response)
    summary_response = conversational_chain_revised(summary_input, session['text'])
    session['summary_response'] = summary_response

    # Function 2: Outline clauses

    # clauses_response = session['clauses_response']
    clauses_response = conversational_chain_revised(outline_input, session['text'])
    clauses_response = clauses_response.replace("-"," ")
    clauses_response = clauses_response.split("&&&")
    # print(clauses_response)

    # Function 3: Identify action items

    # items_response = session['items_response']
    items_response = conversational_chain_revised(action_items_input, session['text'])
    items_response = items_response.replace("-"," ")
    items_response = items_response.split("&&&")
    # print(items_response)

    # Function 4: Explain potential red flags
    flags_response = conversational_chain_revised(red_flags_input, session['text'])
    flags_response = flags_response.replace("-","")
    flags_response = flags_response.split("&&&")
    flags_response = [i for i in flags_response if len(i)>5 ]
    # print(flags_response)

    # Function 5: Outline money matters
    money_response = conversational_chain_revised(outline_money_input, session['text'])
    money_response = money_response.replace("-","")
    money_response = money_response.split("&&&")
    money_response = [i for i in money_response if len(i)>5 ]
    # print(money_response)

    # Function 6: Write questions for your attorney
    questions_response = conversational_chain_revised(write_questions_input, session['text'])
    questions_response = questions_response.replace("-","")
    questions_response = questions_response.split("&&&")
    questions_response = [i for i in questions_response if len(i)>5 ]
    # print(questions_response)

    # Function 7: Explain glossary
    glossary_response = conversational_chain_revised(explain_glossary_input, session['text'])
    glossary_response = glossary_response.replace("-","")
    glossary_response = glossary_response.split("&&&")
    glossary_response = [i for i in glossary_response if len(i)>5 ]
    # print(glossary_response)

    return render_template("analysis_legal.html",
                    summary_response=summary_response,
                    clauses_response=clauses_response,
                    items_response = items_response,
                    flags_response = flags_response,
                    money_response = money_response,
                    questions_response = questions_response,
                    glossary_response = glossary_response
                )


#---------------------------------------- Legal ---------------------------------------

#---------------------------------------- Policy ---------------------------------------


@app.route("/analysis_policy", methods=["GET","POST"])
@login_required
def analysis_policy():
    if request.method == "POST":
        if len(user_memory.load_memory_variables({})["chat_history"].split("\n")) :
            question = request.form['msg']
            persist_directory="DB"
            vectordb = Chroma(persist_directory=persist_directory,embedding_function=embeddings, collection_name=session['user_id'])
            retriever = vectordb.as_retriever(search_type="mmr", search_kwargs={"k":1})
            docs = retriever.get_relevant_documents(question,max_tokens=1024)
            prompt = PromptTemplate(template = prompt_template_policy, input_variables = ["context", "question", "chat_history"],max_tokens=1024)
            chain = load_qa_chain(llm, chain_type="stuff", prompt=prompt, memory=user_memory)
            response = chain(
                {"input_documents":docs, "question": question}
                , return_only_outputs=True)
            return str(response['output_text'])
        else:
            return "You have exceeded your maximum chat limit"

    summary_response = ""
    intended_audience_response = ""
    key_clauses_response = ""
    items_response = ""

    # Function 4: Explain potential red flags
    summary_response = conversational_chain_revised(summary_input_policy, session['text'])
    # print(flags_response)

    # Function 5: Outline money matters
    intended_audience_response = conversational_chain_revised(intended_audience_input_policy, session['text'])
    intended_audience_response = intended_audience_response.replace("-","")
    intended_audience_response = intended_audience_response.split("&&&")
    intended_audience_response = [i for i in intended_audience_response if len(i)>5 ]
    # print(money_response)

    # Function 6: Write questions for your attorney
    key_clauses_response = conversational_chain_revised(outline_input_policy, session['text'])
    key_clauses_response = key_clauses_response.replace("•","")
    key_clauses_response = key_clauses_response.replace("-","")
    key_clauses_response = key_clauses_response.split("&&&")
    key_clauses_response = [i for i in key_clauses_response if len(i)>5 ]
    # print(questions_response)

    # Function 7: Explain glossary
    items_response = conversational_chain_revised(action_items_input_policy, session['text'])
    items_response = items_response.replace("•","")
    items_response = items_response.replace("-","")
    items_response = items_response.split("&&&")
    items_response = [i for i in items_response if len(i)>5 ]
    # print(glossary_response)

    return render_template("analysis_policy.html",
                    summary_response = summary_response,
                    intended_audience_response = intended_audience_response,
                    key_clauses_response = key_clauses_response,
                    items_response = items_response
                )


#---------------------------------------- Policy ---------------------------------------

#---------------------------------------- Extraction ---------------------------------------


@app.route("/analysis_extraction", methods=["GET","POST"])
@login_required
def format_extraction():
    print("This is session text : ", session['text'])
    if 'format_extraction' in session and session['format_extraction']:
        flattened_response = session['format_extraction']
    else:
        json_response = conversational_chain_revised_json(json_output, session['text'])
        flattened_response = extract_key_value_pairs(json_response)
        session['format_extraction'] = flattened_response

    return render_template("analysis_extraction.html", json_response=flattened_response)


@app.route("/transcript_extraction", methods=["GET","POST"])
@login_required
def transcript_extraction():
    data = session['text']
    return render_template("transcript_extraction.html", data=data)


@app.route("/json_extraction", methods=["GET","POST"])
@login_required
def json_extraction():
    if 'json_extraction' in session and session['json_extraction']:
        json_response = session['json_extraction']
    else:
        json_response = conversational_chain_revised_json(json_output, session['text'])
        session['json_extraction'] = json_response

    return render_template("json_extraction.html", json_response=json_response)


# @app.route("/checkbox_extraction", methods=["GET","POST"])
# @login_required
# def checkbox_extraction():
#     if 'checkbox_response' in session and session['checkbox_response']:
#         checkbox_response = session['checkbox_response']
#     else:
#         checkbox_response = conversational_chain_revised_json(checkbox_output, session['text'])
#         session['checkbox_response'] = checkbox_response

#     return render_template("checkbox_extraction.html", json_response=checkbox_response)

@app.route("/checkbox_extraction", methods=["GET", "POST"])
def checkbox_extraction():
    if 'checkbox_response' in session and session['checkbox_response']:
        # Retrieve the response from the session
        structured_checkboxes_response = session['checkbox_response']
    else:
        # Process and structure the checkbox response
        response_checkbox = process_image_pdf_4(session['path'])
        structured_checkboxes_response = structure_checkbox_response(
            structure_student_response_prompt, response_checkbox
        )
        # Save the response in the session
        session['checkbox_response'] = structured_checkboxes_response

    # Render the template with the structured response
    return render_template("checkbox_extraction.html", json_response=structured_checkboxes_response)

@app.route("/Student_verification", methods=["GET", "POST"])
def student_verify():
    if 'verification' in session and session['verification']:
        verification_response = session['verification']
    else:
        verification_response = conversational_chain_student(student_verification, session['json_extraction'], session['text'])
        session['verification'] = verification_response

    return render_template("json_extraction_1.html", json_response=verification_response)


@app.route("/Sign_verification", methods=["GET", "POST"])
def sign_verification():
    if 'sign_verification' in session and session['sign_verification']:
        structure_sign_verification = session['sign_verification']
    else:
        # sign_verification_response = process_image_pdf_3(session['path'])
        # structure_sign_verification = structure_student_verification(student_sign_verification, sign_verification_response)
        # session['sign_verification'] = structure_sign_verification

        # final_response_list_json , final_response_str_json = process_image_pdf_3(session['path'])
        final_response_str_json = process_image_pdf_3(session['path'])
        structure_sign_verification = structure_student_verification(student_sign_verification_structurize, final_response_str_json)
        session['sign_verification'] = structure_sign_verification
        # print(f"final response list : {final_response_list_json}")
        print("-------"*20)
        print(f"Final response string : {final_response_str_json}")
        print("-------"*20)
        print(f"Final structured json response : {structure_sign_verification}")


    return render_template("json_extraction_1.html", json_response=session['sign_verification'])


#---------------------------------------- Extraction ---------------------------------------

#---------------------------------------- Medical ---------------------------------------


@app.route("/analysis_medical", methods=["GET","POST"])
@login_required
def analysis_medical():
    if 'format_medical' and 'personal_medical' in session and session['format_medical']:
        json_response = session['format_medical']
        personal_response = session['personal_medical']
    else:
        json_response = conversational_chain_revised_json(json_output_medical, session['text'])
        personal_response = conversational_chain_revised_json(personal_output_medical, session['text'])
        session['format_medical'] = json_response
        session['personal_medical'] = personal_response

    return render_template("analysis_medical.html", json_response=json_response, personal_response=personal_response)

@app.route("/transcript_medical", methods=["GET","POST"])
@login_required
def transcript_medical():
    data = session['text']
    return render_template("transcript_medical.html", data=data)


@app.route("/json_medical", methods=["GET","POST"])
@login_required
def json_medical():
    if 'json_medical' in session and session['json_medical']:
        json_response = session['json_medical']
    else:
        json_response = conversational_chain_revised_json(json_output_medical, session['text'])
        session['json_medical'] = json_response

    return render_template("json_medical.html", json_response=json_response)


#---------------------------------------- Medical ---------------------------------------

#---------------------------------------- Text Analyser --------------------------------------

# In-memory blacklist for demonstration purposes
blacklist = set()

# Check if the token is in the blacklist
@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(jwt_header, jwt_payload):
    jti = jwt_payload['jti']
    return jti in blacklist

@app.route('/api/refresh-token', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(access_token=new_access_token), 200

## Function for decrease count in database
def decrease_data_count(r_id):
    logging.info("decrease data from chat method initiated")
    user = Report.query.filter_by(r_id=r_id).first()
    if user:
        user.chat_count -= 1
        db.session.commit()
        logging.info("chat number decreased")


# @app.route('/api/')
# def index():
#     logging.info("index route called")
#     return "Hello World"


# @app.route('/api/register', methods=['POST'])
# def register():
#     print("Got request for user register")
#     data = request.get_json()
#     first_name = data.get('first_name')
#     last_name = data.get('last_name')
#     email = data.get('email')
#     password = data.get('password')

#     if User.query.filter_by(email=email).first():
#         print("User already exists")
#         return jsonify({'error': 'User already exists'}), 400

#     try:
#         new_user = User(
#             first_name=first_name,
#             last_name=last_name,
#             email=email,
#             password=generate_password_hash(password),
#         )
#         db.session.add(new_user)
#         db.session.commit()
#     except Exception as e:
#         logging.error(f"Error occurred while registering user: {str(e)}")
#         print("Error occurred while registering user: ", e)
#         return jsonify({'error': str(e)}), 500

#     # Create user in Supabase
#     response = supabase.auth.sign_up({'email': email, 'password': password})
#     user = User.query.filter_by(email=email).first()

#     access_token = create_access_token(identity=user.id)
#     refresh_token = create_refresh_token(identity=user.id)

#     return jsonify({
#         'message': {
#             'user_id': user.id,
#             'email': user.email,
#             'first_name': user.first_name,
#             'last_name': user.last_name
#         },
#         'access_token': access_token,
#         'refresh_token': refresh_token
#     }), 200


# @app.route('/api/login', methods=['POST'])
# def login():
#     data = request.get_json()
#     email = data.get('email')
#     password = data.get('password')
#     print(email)
#     print(password)

#     user = User.query.filter_by(email=email).first()
#     print(user)
#     if not user or not check_password_hash(user.password, password):
#         return jsonify({'error': 'Invalid email or password'}), 400

#     # Check if the user's email is verified in Supabase
#     try:
#         response = supabase.auth.sign_in_with_password({
#             'email': email,
#             'password': password
#         })

#     except Exception as e:
#         print(e)
#         # Handle email not confirmed error
#         if isinstance(e, gotrue.errors.AuthApiError) and 'Email not confirmed' in str(e):
#             return jsonify({'error': 'Email not verified'}), 400
#         else:
#             return jsonify({'error': 'Login failed'}), 500

#     # Check if email is confirmed
#     if not response.user.email_confirmed_at:
#         return jsonify({'error': 'Email not verified'}), 400

#     # Generate JWT token
#     access_token = create_access_token(identity=user.id)
#     refresh_token = create_refresh_token(identity=user.id)

#     return jsonify({
#         'message': {
#             'user_id': user.id,
#             'email': user.email,
#             'first_name': user.first_name,
#             'last_name': user.last_name
#         },
#         'access_token': access_token,
#         'refresh_token': refresh_token
#     }), 200

# @app.route('/api/update_profile', methods=['PUT'])
# @jwt_required()
# def update_profile():
#     user_id = get_jwt_identity()
#     data = request.get_json()
#     user = User.query.get(user_id)

#     if not user:
#         return jsonify({'message': 'User not found'}), 404

#     # Update the user's details
#     user.first_name = data.get('first_name', user.first_name)
#     user.last_name = data.get('last_name', user.last_name)
#     user.email = data.get('email', user.email)

#     try:
#         # Commit the changes to the database
#         db.session.commit()

#         # Return a success message with the updated user details
#         return jsonify({
#             'message': 'Profile updated successfully',
#             'user': {
#                 'id': user.id,
#                 'first_name': user.first_name,
#                 'last_name': user.last_name,
#                 'email': user.email
#             }
#         }), 200

#     except Exception as e:
#         db.session.rollback()  # Rollback in case of an error
#         logging.error(f"Error updating profile: {str(e)}")
#         return jsonify({'error': 'An error occurred while updating the profile'}), 500

# @app.route('/api/userdata', methods=['POST', 'GET'])
# @jwt_required()
# def userdata():
#     if request.method == "POST":
#         try:
#             user_id = get_jwt_identity()
#             user = User.query.get(user_id)

#             if not user:
#                 return jsonify({"error": "User not found"}), 404

#             user_data = {
#                 # "user_id": user.id,
#                 "first_name": user.first_name,
#                 "last_name": user.last_name,
#                 "email": user.email
#             }

#             return jsonify(user_data)
#         except Exception as e:
#             logging.info(f"Exception occurred during get profile data {e}")
#             raise CustomException(e, sys)
#     return jsonify({"error": "Invalid request method"}), 400


# @app.route('/api/change_password', methods=['POST'])
# @jwt_required()
# def change_password():
#     user_id = get_jwt_identity()
#     data = request.get_json()

#     old_password = data.get('old_password')
#     new_password = data.get('new_password')

#     # Get the user by ID
#     user = User.query.get(user_id)

#     if not user:
#         return jsonify({'error': 'User not found'}), 404

#     if new_password == old_password:
#         return jsonify({'error': 'Your new password is same as old password..!'}), 400

#     # Check if the old password is correct
#     if not check_password_hash(user.password, old_password):
#         return jsonify({'error': 'Old password is incorrect'}), 400

#     # Update password in Supabase
#     try:
#         supabase.auth.update_user({
#             'password': new_password
#         })
#     except Exception as e:
#         logging.error(f"Error updating password in Supabase: {str(e)}")
#         return jsonify({'error': 'Failed to update password in Supabase'}), 500

#     # Hash the new password and update it
#     user.password = generate_password_hash(new_password)

#     try:
#         db.session.commit()
#         return jsonify({'message': 'Password updated successfully'}), 200
#     except Exception as e:
#         db.session.rollback()  # Rollback in case of an error
#         logging.error(f"Error changing password: {str(e)}")
#         return jsonify({'error': 'An error occurred while changing the password'}), 500


# @app.route('/api/forgot_password', methods=['POST'])
# def forgot_password():
#     data = request.get_json()
#     email = data.get('email')

#     if not email:
#         return jsonify({'error': 'Email is required'}), 400

#     # Generate reset token
#     token, hashed_token, expiration_time = generate_reset_token()
#     reset_link = f"http://localhost:5173/new_password?token={token}"

#     try:
#         # send_password_reset_email(email, reset_link)
#         supabase.auth.reset_password_email(email, {'redirect_to':'http://localhost:5173/new_password'})

#         return jsonify({'message': 'Password reset link sent to your email.'}), 200
#     except Exception as e:
#         return jsonify({'error': 'Failed to send reset link. Please try again later.'}), 500

# @app.route('/api/new_password', methods=['POST'])
# def set_new_password():
#     data = request.get_json()
#     email = data.get('email')
#     token = data.get('token')
#     new_password = data.get('password')
#     print(email)
#     print("new_password: ", new_password)
#     print("token: ", token)

#     # Validate input
#     if not email or not new_password:
#         return jsonify({'error': 'Email and password are required'}), 400
#     print("Email and password are present")

#     if not token:
#         return jsonify({'error': 'Token is required'}), 400
#     print("Token is present")

#     # Find user by email in your custom User table
#     user = User.query.filter_by(email=email).first()
#     print(user)

#     if not user:
#         return jsonify({'error': 'User not found'}), 404
#     print("User is present")

#     try:
#         response = supabase.auth.verify_otp({"token_hash": token, "type": "recovery"})
#     except Exception as e:
#         print("Error occured while exchanging code for session: ", e)

#     # Hash the new password
#     hashed_password = generate_password_hash(new_password)
#     print(hashed_password)

#     # Update password in your local User table
#     user.password = hashed_password

#     try:
#         # supabase.auth.update_user({
#         # "password": new_password
#         # })
#         # supabase.auth.reset_password_email(new_password)
#         response = supabase.auth.update_user({"password": new_password})
#         print("Response from supabase: ", response)

#     except Exception as e:
#         print("Error occured while resetting password in supabase : ", e)
#         logging.error(f"Error updating password in Supabase: {str(e)}")
#         return jsonify({'error': 'Failed to update password in Supabase'}), 500

#     # Save changes to your local database
#     try:
#         db.session.commit()
#         return jsonify({'message': 'Password updated successfully'}), 200
#     except Exception as e:
#         print("Error occuring while storing data in database : ",e)
#         db.session.rollback()
#         logging.error(f"Error updating password in the local database: {str(e)}")
#         return jsonify({'error': 'An error occurred while updating the password'}), 500


# @app.route('/api/profile', methods=['POST', 'GET'])
# @jwt_required()
# def profile_data():
#     if request.method == "POST":
#         try:
#             user_id = get_jwt_identity()
#             all_reports = Report.query.filter_by(u_id=user_id).order_by(Report.r_id.desc()).all()
#             list_all = []
#             for report in all_reports:
#                 report_id = report.r_id
#                 saving = report.saving
#                 withholding = report.withholding
#                 tax_credits = report.tax_credits
#                 json_data = {
#                     "report_id": report_id,
#                     "saving": saving,
#                     "withholding": withholding,
#                     "tax_credits": tax_credits,
#                     "date": report.date,
#                     "plan": report.plan,
#                     "chat_count": report.chat_count,
#                     "call_count": report.call_count
#                 }
#                 list_all.append(json_data)
            
#             return jsonify(list_all)
#         except Exception as e:
#             logging.info(f"Exception occurred during get profile data {e}")
#             raise CustomException(e, sys)
#     return jsonify({"error": "Invalid request method"}), 400

# @app.route('/api/plan', methods=['POST', 'GET'])
# @jwt_required()
# def plan():
#     if request.method == "POST":
#         data = request.get_json()
#         report_id = data.get('r_id')
#         all_reports = Report.query.filter_by(r_id=report_id).all()
#         for report in all_reports:
#             user_id = report.u_id
#             plan = report.plan
#         return jsonify(user_id=user_id, plan=plan)


@app.route('/upload_w2_form', methods=["POST", "GET"])
# @cross_origin(allow_headers=True, supports_credentials=True)
@jwt_required()
def upload_file():
    user_id = get_jwt_identity()

    if request.method == "POST":
        try:
            logging.info("File uploaded")
            app.logger.info(f"Received request from {request.origin}")

            if 'file' not in request.files:
                return jsonify(message="No file uploaded"), 400

            file = request.files['file']
            user_plan = request.form.get('plan')
            user_id = str(user_id)

            time = datetime.now()
            data_str = get_w2_data(file)
            time_after = datetime.now()
            print("Time: ")
            print(time_after - time)


            extracted_data = {}
            data = json.loads(data_str)

            if 'result' in data and len(data['result']) > 0:
                for item in data['result'][0].get('prediction', []):
                    label = item.get('label')
                    ocr_text = item.get('ocr_text')
                    if label and ocr_text:
                        extracted_data[label] = ocr_text

            # Assign chat_count and call_count based on user_plan
            if user_plan == "basic":
                user_chat_count = 10
                user_call_count = 0
            elif user_plan == "premium":
                user_chat_count = 30
                user_call_count = 0
            elif user_plan == "premium+":
                user_chat_count = 50
                user_call_count = 1
            else:
                return jsonify({"error": "Invalid user plan"}), 400

            new_data = json.dumps(extracted_data)  # Convert extracted_data to JSON string
            report_data = Report(u_id=user_id, w2_form_data=new_data, date=datetime.utcnow(), plan=user_plan, chat_count=user_chat_count, call_count=user_call_count)

            db.session.add(report_data)
            db.session.commit()

            report_id = report_data.r_id  # Assuming r_id is auto-generated or set by database
            return jsonify({"r_id": report_id, "user_id": user_id}), 200

        except KeyError as ke:
            logging.error(f"KeyError: {ke}")
            return jsonify({"error": "Invalid data format in uploaded file"}), 400

        except Exception as e:
            logging.error(f"Exception occurred during file upload and data extraction: {e}")
            raise CustomException(e, sys)  # Handle CustomException as needed

    else:
        return jsonify({"response": "Only POST requests are supported for file upload"}), 405


# @app.route('/api/create-checkout-session', methods=['POST'])
# @jwt_required()
# def create_checkout_session():
#     data = request.json
#     package = data.get('package')

#     if package not in PACKAGE_PRICES:
#         return jsonify({'error': 'Invalid package selected'}), 400

#     try:
#         session = stripe.checkout.Session.create(
#             payment_method_types=['card'],
#             line_items=[{
#                 'price_data': {
#                     'currency': 'usd',
#                     'product_data': {
#                         'name': package.capitalize() + ' Package',
#                     },
#                     'unit_amount': PACKAGE_PRICES[package],
#                 },
#                 'quantity': 1,
#             }],
#             mode='payment',
#             success_url='http://3.18.163.246/report',
#             cancel_url='http://3.18.163.246/upload',
#         )
#         return jsonify({'id': session.id})
#     except Exception as e:
#         return jsonify({'error': str(e)}), 500
    

@app.route("/textAnalyser/report", methods=["GET", "POST"])
# @cross_origin(supports_credentials=True, allow_headers=True)
@jwt_required()
def report():
    if request.method == "POST":
        user_id = get_jwt_identity()
        logging.info("Report generation started")
        try:
            type = request.form.get("type")
            report_id = request.form.get('r_id')

            report_data = Report.query.filter_by(r_id=report_id, u_id=user_id).first()
            # report_data = Report.query.filter_by(r_id=report_id).first()
            if not report_data:
                return jsonify({'error': 'Report not found'}), 404

            w2_data = report_data.w2_form_data
            if type == "savings":
                result = report_data.saving
                if result:
                    result = result.split("&&&")
                    return jsonify({"type": f"{type}", "report": result}), 200
                else:
                    template = f"""
                        Your objective is to provide detailed, specific tax savings guidance to the tax filer. Base your suggestions on the filer’s W-2 Boxes 1 through 14, and provide strategies of how they can save current and future taxes.  Make responses easy enough to process for someone without a tax or financial background.  In your analysis, please try to include the following items when reasonable: 1) 401(k)/403(b)/457 - pre-tax vs Roth, 2) IRA - traditional, Roth, non-deductible with Roth conversion, 3) HSA (health savings account), 4) FSA (flexible savings account), 5) dependent care benefits, and 6) emergency savings withdrawal of $1,000. If the filer is already taking advantage of certain strategies such as 401(k), HSA, etc…please mention something along the lines of “Great job for taking advantage of…”.  For the IRA recommendation, please consider income phaseout limits based on a Single taxpayer, and if they make too much for a Roth IRA please mention the backdoor Roth option. Do not give abstract and arbitrary suggestions like 'consult a tax or investment professional'. Do not include each and every data point from the dataset in your answer, but use specific numbers where necessary. Your response should ONLY be bullet points, without any headers, introduction or conclusion. Each bullet point should have a prefix of '&&&', and should not be in bold. Only provide your greatest 6-7 points, not more. Do not forget these rules.

                        Here is the filer's W2 data: {w2_data}
                        """
                    context = vectordb.similarity_search(template, k=5)
                    chain = savings_chain()
                    result = chain.invoke({"w2_data":w2_data, "context":context})
                    if result:
                        report_data.saving = result
                        db.session.commit()
                        result = result.split("&&&")
                    return jsonify({"type": f"{type}", "report": result}), 200

            elif type == "withholding":
                result = report_data.withholding
                if result:
                    result = result.split("&&&")
                    return jsonify({"type": f"{type}", "report": result}), 200
                else:
                    template = f"""
                        Your objective is to provide brief information regarding the tax filer’s Federal income tax withholding rate.  Make responses easy enough to process for someone without a tax or financial background.  Please give them a percentage with no decimal points of their Box 2 amount divided by Box 1, which tells them their Federal tax withholding rate.  Then compare their Federal tax withholding to the IRS tax tables based on a Single filer, and give a basic recommendation of they are likely under withholding or over with holding Federal income tax.  Please tell them this analysis is based on filing as Single, and to use the result with utmost caution.  Also tell them to reach out to their tax advisor to more accurately determine if they are likely under or over withholding based on their more recent paystub, and considering their other income sources.

                        Here is the filer's W2 data: {w2_data}
                        """
                    context = vectordb.similarity_search(template, k=5)
                    chain = withholding_chain()
                    result = chain.invoke({"w2_data":w2_data, "context":context})
                    if result:
                        report_data.withholding = result
                        db.session.commit()
                        result = result.split("&&&")
                    return jsonify({"type": f"{type}", "report": result}), 200

            elif type == "tax_credits":
                result = report_data.tax_credits
                if result:
                    result = result.split("&&&")
                    return jsonify({"type": f"{type}", "report": result}), 200
                else:
                    template = """
                        Your objective is to provide detailed guidance on claiming the following tax credits: 1) Child Tax Credit, 2) Child and Dependent Care Credit, 3) American Opportunity Tax Credit, 4) Lifetime Learning Credit, and 5) Residential Energy Credits.  Make responses easy enough to process for someone without a tax or financial background.  Your response should ONLY be bullet points, without any headers, introduction or conclusion. Each bullet point should have a prefix of '&&&', and should not be in bold. Only provide your greatest 5-6 points, not more. Do not forget these rules.

                        Here is the filer's W2 data: {w2_data}
                        """
                    context = vectordb.similarity_search(template, k=5)
                    chain = tax_credits_chain()
                    result = chain.invoke({"w2_data":w2_data, "context":context})
                    if result:
                        report_data.tax_credits = result
                        db.session.commit()
                        result = result.split("&&&")
                    return jsonify({"type": f"{type}", "report": result}), 200

            else:
                return jsonify({"error": "Invalid report type"}), 400

        except Exception as e:
            logging.info(f"Exception occurred during Report Generation: {e}")
            raise CustomException(e, sys)

    return jsonify({"error": "Invalid request method"}), 400


# @app.route("/api/credit", methods=["GET", "POST"])
# @jwt_required()
# def fetch_call_credit():
#     if request.method == "POST":
#         try:
#             data = request.get_json()
#             report_id = data.get('report_id')
#             report = Report.query.filter_by(r_id=report_id).first()
#             return jsonify({"credit": report.call_count}), 200
#         except Exception as e:
#             logging.info(f"Exception occured getting call data {e}")
#             raise CustomException(e, sys)


# @app.route("/api/meeting-booked", methods=["GET", "POST"])
# @jwt_required()
# def meeting_booked():
#     try:
#         data = request.get_json()
#         if not data:
#             return jsonify({"error": "No data provided"}), 400

#         report_id = data.get('report_id')
#         if not report_id:
#             return jsonify({"error": "No report_id provided"}), 400

#         report = Report.query.filter_by(r_id=report_id).first()
#         if not report:
#             return jsonify({"error": "Report not found"}), 404

#         if report.call_count <= 0:
#             return jsonify({"error": "No calls remaining"}), 400

#         report.call_count -= 1
#         db.session.commit()

#         return jsonify({"response": "Meeting booked successfully", "calls_remaining": report.call_count}), 200

#     except Exception as e:
#         logging.error(f"Exception occurred while booking meeting: {str(e)}", exc_info=True)
#         db.session.rollback()
#         return jsonify({"error": "An unexpected error occurred"}), 500


@app.route("/textAnalyser/count", methods=["GET", "POST"])
@jwt_required()
def report_chat_count():
    if request.method == "POST":
        try:
            data = request.get_json()
            report_id = data.get('report_id')

            report = Report.query.filter_by(r_id=report_id).first()
            return jsonify({"count": report.chat_count}), 200

        except Exception as e:
            logging.info(f"Exception occurred during get profile data {e}")
            raise CustomException(e, sys)
    return jsonify({"error": "Invalid request method"}), 400


@app.route('/textAnalyser/chat', methods=["GET", "POST"])
@jwt_required()
def chat():
    if request.method == "POST":
        logging.info("Chat started question received")
        try:
            question = request.form.get('question')
            user_id = get_jwt_identity()
            r_id = request.form.get("r_id")
            limits = json.loads(Path("./analyser/2024_limits.json").read_text())
            if Report.query.filter_by(r_id=r_id).first().chat_count > 0:
                decrease_data_count(r_id)
                chain = get_conversational_chain()
                context = vectordb.similarity_search(question, k=5)
                w2_data = Report.query.filter_by(r_id=r_id).first().w2_form_data
                saving = Report.query.filter_by(r_id=r_id).first().saving
                withholding = Report.query.filter_by(r_id=r_id).first().withholding
                tax_credits = Report.query.filter_by(r_id=r_id).first().tax_credits
                recomendations = {'saving': {saving}, 'withholding': {withholding}, 'tax_credits': {tax_credits}}
                result = chain.invoke({"question": question,"data": w2_data, "context": context, 'recommendations':str(recomendations), "limits": limits})
                memory.save_context({"input": question}, {"output": result})
                response = jsonify({"response": result}), 200
                return response
            else:
                response = jsonify({"response": "You have exceed all your limit"})
        except Exception as e:
            logging.info(f"Exception occure during Chat {e}")
            raise CustomException(e, sys)
    else:
        logging.info("Received get request instead post")
        response = jsonify({"response":"no post request"})
        return response


# @app.route('/api/logout', methods=['POST'])
# @jwt_required()
# def logout():
#     jti = get_jwt()['jti']
#     blacklist.add(jti)
#     return jsonify({"message": "You have successfully logged out."}), 200



#---------------------------------------- Text Analyser --------------------------------------

if __name__ == '__main__':
    app.run(debug=True, port=5000)
