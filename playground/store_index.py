import os, sys
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import PyPDFDirectoryLoader
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from dotenv import load_dotenv

from playground.logger import logging
from playground.exception import CustomException


load_dotenv()


def store_index():
    logging.info("Store indexing method started for store vectors")
    try:
        loader = PyPDFDirectoryLoader("../data")
        document_text = loader.load()
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        texts = text_splitter.split_documents(document_text)
        DB_Name = "VectorDB"
        embeddings = OpenAIEmbeddings()
        # vectordb = Chroma.from_documents(documents=texts,embedding_function=embeddings,persist_directory=DB_Name)
        db = FAISS.from_documents(texts, embeddings)
        db.save_local("../faiss_index")
    except Exception as e:
        logging.info(f"Exception occure during store index Exception : {e}")
        raise CustomException(e, sys)

store_index()

# question = "give me suggestion regarding investment"
# db3 = Chroma(persist_directory="./VectorDB", embedding_function=OpenAIEmbeddings())
# docs = db3.similarity_search(question)
