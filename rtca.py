import os
import streamlit as st
from langchain import PromptTemplate
from langchain.llms import OpenAI
from masked_ai import masker
from annotated_text import annotated_text
import re

template = """
    Act as a cyber security expert with more than 20 years experience of using the {controls_framework} and all of its controls. Your task is to analyse the security finding (weakness, vulnerability) or testing narrative provided to you and explain which {controls_framework} controls failed to enable them to materialise. Make sure to identify and list ALL controls that contributed to the failures. It is crucial that you are concrete and detailed.

    Here is the description:
    {description}

    Your output should be in the form of a left-aligned markdown table with the following columns:
    - Column "Control", stating the id and name of the control
    - Column "Explanation", explaining why it is considered to have failed, referring specifically to the relevant information in the description"""



def load_LLM(api_key, tokens):
    os.environ['OPENAI_API_KEY'] = api_key
    llm = OpenAI(temperature=0.7, model_name="text-davinci-003", max_tokens=tokens)
    return llm

st.set_page_config(page_title="Red Team Controls Assessor", page_icon=":dart:", layout="wide", initial_sidebar_state="expanded")
st.header("Red Team Controls Assessor 🎯")

def get_input():
    input_text = st.text_area(label="Finding description or attack narrative", placeholder="Finding, weakness or vulnerability discovered, or the narrative of the attack path", height=150, key="description", help="Please describe the finding, weakness or vulnerability discovered, or the narrative of the attack path.")
    return input_text
    
description = get_input()

st.sidebar.header("Using RTCA")

with st.sidebar:
    st.markdown("""
    1. Enter your [OpenAI API key](https://platform.openai.com/account/api-keys) below 🔑
    2. Provide details of the finding or attack narrative 🔥
    3. Select which controls framework you want the analysis to be done against 🛡️
    3. Click **Sanitise** to identify potentially sensitive data in the description and review carefully 📋
    4. Click **Submit** to generate a list of deficient controls 🤯
    """)

    openai_api_key = st.text_input("Enter your OpenAI API key:", type="password")
    st.markdown("""---""")

st.sidebar.header("About")

with st.sidebar:
    st.markdown("RTCA is an AI-powered tool designed to help security professionals assess the performance of security controls in the organisation based on the findings of a red team or similar offensive operation.")
    st.markdown("Red Team reports should provide an assessment of the efficacy of security controls deployed within the organisation, rather than just a list of technical vulnerabilities. Whether the organisation has already adopted frameworks such as NIST CSF or CIS internally, or to introduce them as external reference points for less mature organisations, mapping against these frameworks will increase the readibility, repeatability and ROI of the testing performed. It will also aid the organisation in performing root cause analysis and drive remediation activities.")
    st.markdown("A word of caution: This tool uses OpenAI GPT's API to perform the task, so make sure not to submit any sensitive data. To that end, I've added a PII sanitiser (Cado's Masked-AI) which will highlight potential sensitive data. Review carefully and adjust the description accordingly before submitting.")
    st.markdown("Created by [Kerem Kocaer](https://www.linkedin.com/in/keremkocaer/) as a PoC without any guarantees or support. But if you have cool ideas please feel free to reach out 😊")
    st.markdown("""---""")


st.sidebar.header("Example Description")

with st.sidebar:
    st.markdown("Below is an example description that you can use to test RTCA:")
    st.markdown(">File shares containing sensitive information were identified on servers throughout the CLIENT environment and can be accessed by any internal network users. An attacker or a malicious employee can use this to access a range of sensitive data in open shared folders.")
    st.markdown(">We have found valid credentials for DOMAIN\\account_name within one of the shared folders: //192.168.0.1/Shared/Webconfig. It was possible to authenticate with this credential and summon a command line with its privileges, as well as  to establish an RDP connection with the credentials of the identified user.")
                    
st.sidebar.header("FAQs")

with st.sidebar:
    st.markdown("""
    ### **How does it work?**
    The sanitisation tool uses Cado's [Masked-AI](https://github.com/cado-security/masked-ai) tool to detect and mask potentially sensitive information. When you press the final Submit button, the tool calls OpenAI's API to use a GPT-3 model (text-davinci-003) to generate a list of relevant controls based on your description.
    """)
    st.markdown("""
    ### **Do you store anything provided here?**
    No, RTCA does not store any details you enter here. All entered data is deleted after you close the browser tab.
    """)
    st.markdown("""
    ### **Is this safe?**
    It's definitely a dangerous idea to share bits of a security testing reports with a public service like OpenAI. Make sure the data you sent is fully anonymised and nothing sensitive can be derived from context. This is an experimental tool, use it wisely.
    """)
    st.markdown("""
    ### **Is the output 100% accurate?**
    Definitely not. The output can contain inaccurate information, and is only meant to be used as a starting point. Security standards and frameworks can be intimidating even to seasoned security professionals, so this tool aims to facilitate discussions and ultimately lead to better red team reports. To help RTCA be more accurate, please provide as much detail as possible in the description. Also try running it multiple times with the same input and you'll get different results, some good some less good...
    """)
    st.markdown("""
    ### **How can I improve the tool?**
    - The prompt template for the GPT-3 model could be improved to get better results. The result quality and completeness is quite inconsistent and sometimes disappointing at the moment. 
    - The Cado Masked-AI tool could be improved by adding PII recognizers, maybe to detect hostnames, account names, or similar sensitive data in the context of security operations. Contribute to their awesome work!
    - More standards or frameworks could be added as options. 
    - The code is quick and dirty.
    """)
    st.markdown("""
    ### **Thanks**
    I got inspired to write this when I saw Matt Adams' [STRIDE GPT](https://stridegpt.streamlit.app/). and wanted to experiment building something simple from my world using GPT, python and Streamlit. 
    """)

st.markdown("""---""")
st.markdown("### Sanitisation")
analyse_button = st.button(label="Sanitise")

def split_description(description, masked):
    result = []
    start = 0
    for i in range(len(description)):
        for mask in masked:
            if description[i:i+len(mask)] == mask:
                result.append(description[start:i])
                result.append(mask)
                start = i + len(mask)
                break
    result.append(description[start:])
    return result


annotated_description = ""

if analyse_button and description:
    with st.spinner("Detecting sensitive data in description..."):
        analyzer = masker.Masker(description)
        masked_description = analyzer.masked_data
        lookup = analyzer.get_lookup()

        annotated_description = split_description(masked_description, lookup.keys())

        for idx, x in enumerate(annotated_description):
            if x in lookup.keys():
                annotated_description[idx] = (x, "",)
    
    if len(lookup) != 0:
        st.markdown(":red[There seems to be some sensitive data in the description, and these have been masked for you as shown below. Please review and make sure you've redacted all PII and sensitive data before submitting for controls assessment.]")
    else:
        st.markdown(":green[There doesn't seem to be any sensitive data in the description. However, please review manually and make sure you've redacted all PII and sensitive data before submitting for controls assessment.]")
    annotated_text(annotated_description)
    if 'masked_description' not in st.session_state:
            st.session_state.masked_description = masked_description

    
st.markdown("""---""")
st.markdown("### Controls Assessment")
col1, col2 = st.columns(2)
with col1:
    controls_framework = st.selectbox(
        label="Select the controls framework", 
        options=["NIST CSF Cybersecurity Framework", "CIS Critical Security Controls"], 
        key="controls_framework",
        index=0
        )

include_impact = st.checkbox('Include impact statement')
include_recommendations = st.checkbox('Include recommendations')

if 'masked_description' in st.session_state:
    st.write("Note that the sanitised version of your text will be submitted. Make sure all your changes are reflected in that version.")

submit_button = st.button(label="Submit")

if submit_button and not openai_api_key:
    st.error("Please enter your OpenAI API key.")

elif submit_button and 'masked_description' in st.session_state:
    tokens = 1000

    if include_impact:
        tokens = tokens + 1000
        template = template + """
    - Column "Impact", explaining the impact of this control deficiency to the organisation"""
    if include_recommendations:
        tokens = tokens + 1000
        template = template + """
    - Column "Recommendations", providing some remediation guidelines"""
    
    template=template+"""
    
    YOUR RESPONSE:"""
    
    prompt = PromptTemplate(
        input_variables=["description", "controls_framework"],
        template=template,
    )

    llm = load_LLM(openai_api_key, tokens)
    prompt_with_details = prompt.format(description=st.session_state.masked_description, controls_framework=controls_framework)
   
    with st.spinner("Analysing description to find control deficiencies..."):
        model_output = llm(prompt_with_details)
        st.write(model_output)

elif (analyse_button or submit_button) and not description:
    st.error("Please enter the description before submitting.")

elif submit_button and not 'masked_description' in st.session_state:
    st.error("Please use the Sanitisation tool before submitting.")

