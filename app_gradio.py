import gradio as gr
import requests
import pandas as pd
import wikipedia
import base64
import time
import re
import random
import plotly.express as px
import plotly.graph_objects as go

# ==================== CONFIGURATION ====================
THEME = gr.themes.Soft(
    primary_hue="indigo",
    secondary_hue="emerald"
).set(
    button_primary_background_fill="linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%)",
    button_primary_text_color="white",
)

# ==================== THREAT PREVENTION CLASS ====================
class ThreatPrevention:
    @staticmethod
    def analyze_password_strength(password):
        """AI-based password strength analysis"""
        if not password:
            return "Please enter a password", [], 0
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("❌ Password should be at least 8 characters long")
        
        # Complexity checks
        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("❌ Add uppercase letters")
            
        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("❌ Add lowercase letters")
            
        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("❌ Add numbers")
            
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("❌ Add special characters")
        
        # Common password check
        common_passwords = ["password", "123456", "qwerty", "admin", "welcome"]
        if password.lower() in common_passwords:
            score = 0
            feedback.append("🚨 This is a commonly used password!")
        
        # Strength assessment
        if score >= 5:
            strength = "💪 Very Strong"
        elif score >= 3:
            strength = "👍 Strong"
        elif score >= 2:
            strength = "⚠️ Moderate"
        else:
            strength = "🚨 Weak"
            
        return strength, feedback, score

    @staticmethod
    def generate_secure_password(length=12):
        """Generate secure password"""
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))

    @staticmethod
    def check_phishing_indicators(email_text):
        """Phishing detection"""
        if not email_text:
            return "Please enter text to analyze", {}
            
        indicators = {
            "urgency": len(re.findall(r'urgent|immediately|quick|action required', email_text, re.IGNORECASE)),
            "suspicious_links": len(re.findall(r'http://|https?://[^\s]+', email_text)),
            "personal_info_requests": len(re.findall(r'password|account|login|verify|confirm', email_text, re.IGNORECASE)),
            "suspicious_sender": len(re.findall(r'bank|paypal|amazon|microsoft', email_text, re.IGNORECASE)),
            "grammar_errors": len(re.findall(r'\b(?:pleasse|urgentt|acount|securty)\b', email_text, re.IGNORECASE))
        }
        
        total_score = sum(indicators.values())
        
        if total_score >= 4:
            return "🚨 High phishing risk detected!", indicators
        elif total_score >= 2:
            return "⚠️ Moderate phishing risk detected!", indicators
        else:
            return "✅ Low phishing risk", indicators

# ==================== CORE FUNCTIONS ====================
def scan_url(url):
    """URL scanning function"""
    if not url:
        return "Please enter a URL"
    
    if not url.startswith(("http://", "https://")):
        return "❌ Error: URL must start with http:// or https://"
    
    # Simulate scanning (replace with your VirusTotal API)
    time.sleep(2)  # Simulate API call
    
    # Mock results for demo
    import random
    if random.random() > 0.7:  # 30% chance of malicious
        return "🚨 MALICIOUS URL DETECTED!\n\nThis URL has been flagged by security engines as potentially dangerous."
    else:
        return "✅ URL IS SAFE!\n\nNo malicious activity detected by security engines."

def analyze_password(password):
    """Password analysis with visual feedback"""
    strength, feedback, score = ThreatPrevention.analyze_password_strength(password)
    
    # Create visual progress bar
    progress_html = f"""
    <div style="width: 100%; background: #e5e7eb; border-radius: 10px; margin: 10px 0;">
        <div style="width: {score * 20}%; background: {'#ef4444' if score < 2 else '#f59e0b' if score < 4 else '#10b981'}; 
             height: 20px; border-radius: 10px; transition: all 0.3s ease;"></div>
    </div>
    <div style="text-align: center; font-weight: bold; color: {'#ef4444' if score < 2 else '#f59e0b' if score < 4 else '#10b981'};">
        {strength}
    </div>
    """
    
    feedback_text = "\n".join(feedback) if feedback else "✅ Excellent! Your password meets all security criteria!"
    
    return progress_html, feedback_text

def generate_password():
    """Generate secure password"""
    return ThreatPrevention.generate_secure_password()

def check_phishing(email_text):
    """Phishing detection"""
    result, indicators = ThreatPrevention.check_phishing_indicators(email_text)
    
    # Format indicators
    indicators_text = "\n".join([f"• {k.replace('_', ' ').title()}: {v} instances" for k, v in indicators.items()])
    
    return f"{result}\n\n📊 Detection Indicators:\n{indicators_text}"

def wikipedia_search(query):
    """Wikipedia assistant"""
    if not query:
        return "Please enter a question."
    
    try:
        results = wikipedia.search(query)
        if not results:
            return "Sorry, I couldn't find anything on that topic."
        summary = wikipedia.summary(results[0], sentences=3, auto_suggest=False, redirect=True)
        return f"🤖 **Answer:** {summary}"
    except wikipedia.DisambiguationError as e:
        return f"Your query is ambiguous. Did you mean: {', '.join(e.options[:3])}?"
    except wikipedia.PageError:
        return "Sorry, I couldn't find a page matching your query."
    except Exception:
        return "Oops, something went wrong while searching."

def show_analytics():
    """Data visualization demo"""
    # Create sample data
    data = {
        'Type': ['Malware', 'Phishing', 'DDoS', 'Brute Force', 'Insider Threat'],
        'Count': [45, 32, 28, 15, 8]
    }
    df = pd.DataFrame(data)
    
    # Create plot
    fig = px.pie(df, values='Count', names='Type', title='Threat Distribution')
    return fig

# ==================== GRADIO INTERFACE ====================
def create_interface():
    with gr.Blocks(theme=THEME, title="Sentinel-Auth | Security Platform") as demo:
        
        # Header
        gr.Markdown("""
        # 🛡️ Sentinel-Auth Security Platform
        *Enterprise-Grade Threat Detection & AI-Powered Security*
        """)
        
        # Main Tabs
        with gr.Tabs() as tabs:
            
            # === SECURITY DASHBOARD ===
            with gr.Tab("🏠 Security Dashboard"):
                gr.Markdown("### 🎯 Quick Security Overview")
                
                with gr.Row():
                    with gr.Column():
                        # Quick URL Scan
                        gr.Markdown("#### 🌐 Quick URL Scan")
                        quick_url = gr.Textbox(
                            label="Enter URL to scan",
                            placeholder="https://example.com",
                            max_lines=1
                        )
                        quick_scan_btn = gr.Button("🔍 Scan URL", size="sm")
                        quick_result = gr.Textbox(label="Scan Result", interactive=False)
                    
                    with gr.Column():
                        # Security Metrics
                        gr.Markdown("#### 📊 Security Status")
                        gr.Markdown("""
                        <div style='background: linear-gradient(135deg, #10b981, #34d399); color: white; padding: 20px; border-radius: 15px; text-align: center;'>
                            <h3 style='margin: 0;'>🟢 ALL SYSTEMS SECURE</h3>
                            <p style='margin: 10px 0 0 0;'>Real-time monitoring active</p>
                        </div>
                        """)
                
                with gr.Row():
                    gr.Markdown("### ⚡ Quick Actions")
                    with gr.Row():
                        goto_scanner = gr.Button("🔍 Threat Scanner", size="sm")
                        goto_password = gr.Button("🔐 Password Tools", size="sm")
                        goto_phishing = gr.Button("🎣 Phishing Detect", size="sm")
                        goto_ai = gr.Button("🤖 AI Assistant", size="sm")
            
            # === THREAT SCANNER ===
            with gr.Tab("🔍 Threat Scanner"):
                gr.Markdown("### 🌐 URL Security Scanner")
                
                with gr.Row():
                    with gr.Column():
                        url_input = gr.Textbox(
                            label="Enter URL to scan for threats",
                            placeholder="https://suspicious-site.com",
                            info="We'll analyze this URL for potential security threats"
                        )
                        scan_btn = gr.Button("🛡️ Scan for Threats", variant="primary")
                    
                    with gr.Column():
                        scan_result = gr.Textbox(
                            label="Threat Analysis Result",
                            lines=6,
                            interactive=False
                        )
                
                # Connect function
                scan_btn.click(
                    scan_url,
                    inputs=url_input,
                    outputs=scan_result
                )
            
            # === PASSWORD SECURITY ===
            with gr.Tab("🔐 Password Security"):
                gr.Markdown("### 🎯 Password Strength Analyzer")
                
                with gr.Row():
                    with gr.Column():
                        password_input = gr.Textbox(
                            label="Enter password to analyze",
                            placeholder="Your password here...",
                            type="password",
                            info="We'll check your password strength securely"
                        )
                        analyze_btn = gr.Button("🔍 Analyze Password", variant="primary")
                        
                        gr.Markdown("### 🎲 Password Generator")
                        generate_btn = gr.Button("✨ Generate Secure Password")
                        generated_pw = gr.Textbox(
                            label="Generated Secure Password",
                            interactive=False
                        )
                    
                    with gr.Column():
                        strength_display = gr.HTML(label="Password Strength")
                        feedback_display = gr.Textbox(
                            label="Improvement Suggestions",
                            lines=6,
                            interactive=False
                        )
                
                # Connect functions
                analyze_btn.click(
                    analyze_password,
                    inputs=password_input,
                    outputs=[strength_display, feedback_display]
                )
                
                generate_btn.click(
                    generate_password,
                    outputs=generated_pw
                )
            
            # === PHISHING DETECTION ===
            with gr.Tab("🎣 Phishing Detection"):
                gr.Markdown("### 📧 Email Phishing Analyzer")
                
                with gr.Row():
                    with gr.Column():
                        email_input = gr.Textbox(
                            label="Paste email or message content",
                            placeholder="Dear user, your account has been compromised. Click here to verify your identity immediately...",
                            lines=6,
                            info="We'll analyze the text for phishing indicators"
                        )
                        phishing_btn = gr.Button("🔍 Analyze for Phishing", variant="primary")
                    
                    with gr.Column():
                        phishing_result = gr.Textbox(
                            label="Phishing Analysis Result",
                            lines=8,
                            interactive=False
                        )
                
                phishing_btn.click(
                    check_phishing,
                    inputs=email_input,
                    outputs=phishing_result
                )
            
            # === AI ASSISTANT ===
            with gr.Tab("🤖 AI Assistant"):
                gr.Markdown("### 🧠 Wikipedia Security Assistant")
                
                with gr.Row():
                    with gr.Column():
                        wiki_input = gr.Textbox(
                            label="Ask me anything about cybersecurity",
                            placeholder="What is phishing? How does two-factor authentication work? Explain malware types...",
                            lines=3
                        )
                        wiki_btn = gr.Button("🔍 Search Wikipedia", variant="primary")
                    
                    with gr.Column():
                        wiki_output = gr.Textbox(
                            label="AI Response",
                            lines=6,
                            interactive=False
                        )
                
                # Quick questions
                gr.Markdown("### 💡 Quick Questions")
                with gr.Row():
                    quick_q1 = gr.Button("What is malware?")
                    quick_q2 = gr.Button("Strong passwords?")
                    quick_q3 = gr.Button("Network security?")
                    quick_q4 = gr.Button("Social engineering?")
                
                # Connect functions
                wiki_btn.click(
                    wikipedia_search,
                    inputs=wiki_input,
                    outputs=wiki_output
                )
                
                # Quick question handlers
                quick_q1.click(lambda: "What is malware and how does it work?", outputs=wiki_input)
                quick_q2.click(lambda: "How to create strong secure passwords?", outputs=wiki_input)
                quick_q3.click(lambda: "What is network security?", outputs=wiki_input)
                quick_q4.click(lambda: "What are social engineering attacks?", outputs=wiki_input)
            
            # === ANALYTICS ===
            with gr.Tab("📊 Analytics"):
                gr.Markdown("### 📈 Security Analytics Dashboard")
                
                with gr.Row():
                    with gr.Column():
                        plot = gr.Plot(label="Threat Distribution")
                        update_plot = gr.Button("🔄 Update Analytics")
                    
                    with gr.Column():
                        gr.Markdown("""
                        ### 🎯 Security Metrics
                        - **Total Scans Today:** 127
                        - **Threats Detected:** 3
                        - **Success Rate:** 97.6%
                        - **Avg Response Time:** 2.3s
                        """)
                
                update_plot.click(show_analytics, outputs=plot)
        
        # === TAB NAVIGATION ===
        goto_scanner.click(lambda: gr.Tabs(selected=1), outputs=tabs)
        goto_password.click(lambda: gr.Tabs(selected=2), outputs=tabs)
        goto_phishing.click(lambda: gr.Tabs(selected=3), outputs=tabs)
        goto_ai.click(lambda: gr.Tabs(selected=4), outputs=tabs)
        
        # Footer
        gr.Markdown("""
        ---
        <div style="text-align: center; color: #6b7280;">
            <p>🛡️ <b>Sentinel-Auth Security Platform</b> | Powered by AI & Real-time Threat Intelligence</p>
        </div>
        """)
    
    return demo

# ==================== LAUNCH APPLICATION ====================
if __name__ == "__main__":
    # Create interface
    app = create_interface()
    
    # Launch with settings
    app.launch(
        server_name="0.0.0.0",    # Accessible from network
        server_port=7860,         # Default port
        share=False,              # Set to True for public URL
        debug=True,               # Show errors
        show_error=True           # Display errors to user
    )
