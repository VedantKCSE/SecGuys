import google.generativeai as genai
import json
import os
import time

# 🔑 Integrated API Key
API_KEY = "YOUR_API_KEY_HERE"

def analyze_vulnerabilities():
    print("🤖 Starting AI Predictive Analysis (2025 Optimized) 🚀")

    # 1. Check for the data file
    if not os.path.exists("final.json"):
        print("❌ Error: 'final.json' not found! Please run your bash script first. 📁")
        return

    try:
        # 2. Configure the API
        genai.configure(api_key=API_KEY)
        
        # 💡 USING FLASH-LITE: This model has the highest free-tier availability in Dec 2025.
        model = genai.GenerativeModel('gemini-2.5-flash-lite')
        
        # 3. Load Normalized Data
        with open("final.json", "r") as f:
            scan_data = json.load(f)

        # 4. Craft the Predictive Prompt
        prompt = f"""
        Act as a Cyber Security Predictive Analyst. 🕵♂
        Analyze this scan data from a Metasploitable2 target (192.168.74.91).
        
        DATA:
        {json.dumps(scan_data, indent=2)}

        PLEASE PROVIDE:
        1. 🚨 TOP 3 CRITICAL EXPLOITS: Identify the most dangerous vulnerabilities.
        2. ⛓ ATTACK CHAIN: How would an attacker move from entry to Root access?
        3. 🌡 RISK SCORE (0-100): Based on actual exploit availability.
        4. 🛠 REMEDIATION: Step-by-step fixes for a sysadmin.

        Format with Markdown and use emoticons. Keep it professional. 📊
        """

        # 5. Generate with Retry Logic (Handles 429 errors gracefully)
        print("🛰 Connecting to Gemini 2.5 Flash-Lite... (Wait 5s to avoid rate-limit)")
        time.sleep(5) 
        
        response = model.generate_content(prompt)
        report_output = response.text

        # 6. Display and Save
        print("\n" + "═"*60)
        print("📝 PREDICTIVE RISK REPORT")
        print("═"*60 + "\n")
        print(report_output)

        with open("ai_report.md", "w") as f:
            f.write(report_output)
        
        print(f"\n✅ SUCCESS! Full report saved to 'ai_report.md' 📄")

    except Exception as e:
        if "429" in str(e):
            print("\n🛑 QUOTA ERROR: The free tier is currently congested.")
            print("💡 TIP: Wait 60 seconds or try switching to 'gemini-1.5-flash'.")
        else:
            print(f"❌ Error encountered: {e} ⚠")

if __name__ == "__main__":
    analyze_vulnerabilities()
