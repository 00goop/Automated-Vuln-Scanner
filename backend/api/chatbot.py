"""
Gemini-powered Security Chatbot
"Shield" - Your AI security assistant with expertise-adaptive responses.
"""
import httpx
import os
from typing import List, Dict, Optional, Any
import json
import logging
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# System prompt for the "Shield" persona
SHIELD_SYSTEM_PROMPT = """You are Shield, a friendly and knowledgeable AI security assistant built into VulnPrioritizer. 

Your personality:
- Calm, reassuring, and supportive - never fear-mongering
- You make users feel smarter and more capable after each interaction
- You explain complex security concepts in plain language
- You provide clear, actionable next steps

Your capabilities:
- Explain vulnerability details and their real-world impact
- Provide step-by-step remediation guidance
- Help users understand priority rankings and ML predictions
- Answer general security questions
- Generate executive summaries

Response guidelines:
1. Adapt your explanation depth based on user expertise:
   - If they use technical terms (CVE, RCE, CVSS), respond technically
   - If they ask "what does this mean?", explain simply
   - Default to accessible language with optional technical details

2. Always provide actionable next steps when relevant

3. Use formatting for clarity:
   - Bullet points for lists
   - Bold for important terms
   - Code blocks for commands

4. Keep responses concise but complete - aim for 2-4 paragraphs max

5. If you don't know something, say so honestly

You have access to the current vulnerability context which will be provided with each message.
"""


class ShieldChatbot:
    """
    Gemini-powered security chatbot with expertise-adaptive responses.
    """
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.model = None
        self.chat_session = None
        self.conversation_history: List[Dict[str, str]] = []
        self.user_expertise_level = "beginner"  # beginner, intermediate, expert
        
        if api_key:
            self._initialize_model()
    
    def _initialize_model(self):
        """Initialize Gemini model."""
        try:
            self.model = os.getenv('GEMINI_MODEL', 'gemini-2.5-flash')
            logger.info("Gemini model initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Gemini model: {e}")
            self.model = None
    
    def chat(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Process a chat message and return response.
        
        Args:
            message: User's message
            context: Optional vulnerability context (current CVE, predictions, etc.)
            
        Returns:
            Dict with response, suggestions, and metadata
        """
        # Detect user expertise level
        self._update_expertise_level(message)
        
        # Build context-aware prompt
        prompt = self._build_prompt(message, context)
        
        if self.model is None:
            return self._fallback_response(message, context)
        
        try:
            # Send to Gemini
            response = httpx.post(
                f'https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent',
                headers={'x-goog-api-key': self.api_key},
                json={'contents': [{'role': 'user', 'parts': [{'text': prompt}]}],
                      'generationConfig': {'temperature': 0.7, 'maxOutputTokens': 1024}},
                timeout=20)
            response.raise_for_status()
            response_text = ''.join(part.get('text', '') for part in
                response.json()['candidates'][0]['content']['parts'])
            
            # Store in history
            self.conversation_history.append({
                "role": "user",
                "content": message
            })
            self.conversation_history.append({
                "role": "assistant", 
                "content": response_text
            })
            
            return {
                "success": True,
                "response": response_text,
                "expertise_level": self.user_expertise_level,
                "suggestions": self._generate_suggestions(message, context),
                "sources": self._extract_sources(context)
            }
            
        except Exception as e:
            logger.error("Gemini request failed (%s)", type(e).__name__)
            return self._fallback_response(message, context)
    
    def _build_prompt(self, message: str, context: Optional[Dict[str, Any]]) -> str:
        """Build context-aware prompt for Gemini."""
        prompt_parts = [SHIELD_SYSTEM_PROMPT]
        
        # Add user expertise context
        prompt_parts.append(f"\n\nUser expertise level: {self.user_expertise_level}")
        
        # Add vulnerability context if available
        if context:
            if "current_cve" in context:
                cve = context["current_cve"]
                prompt_parts.append(f"""
Current vulnerability context:
- CVE ID: {cve.get('cve_id', 'Unknown')}
- Description: {cve.get('description', 'No description')[:500]}
- CVSS Score: {cve.get('cvss_base_score', 'Unknown')}
- Priority Level: {context.get('priority_level', 'Unknown')}
- Has Exploit: {cve.get('has_exploit', False)}
- Has Patch: {cve.get('has_patch', False)}
""")
            
            if "security_score" in context:
                score = context["security_score"]
                prompt_parts.append(f"""
Overall security status:
- Security Score: {score.get('score', 'Unknown')}/100
- Critical issues: {score.get('breakdown', {}).get('critical', 0)}
- High priority: {score.get('breakdown', {}).get('high', 0)}
""")
        
        prompt_parts.append(f"\n\nUser message: {message}")
        
        return "\n".join(prompt_parts)
    
    def _update_expertise_level(self, message: str):
        """Detect and update user expertise level based on their language."""
        message_lower = message.lower()
        
        # Technical terms that indicate expertise
        expert_terms = [
            'cve-', 'cvss', 'rce', 'lfi', 'rfi', 'sqli', 'xss', 'csrf',
            'buffer overflow', 'heap spray', 'rop chain', 'exploit',
            'payload', 'shellcode', 'poc', 'proof of concept',
            'attack vector', 'attack surface', 'privilege escalation'
        ]
        
        intermediate_terms = [
            'vulnerability', 'patch', 'remediation', 'severity',
            'injection', 'authentication', 'authorization'
        ]
        
        beginner_indicators = [
            'what is', 'what does', 'explain', 'help me understand',
            'how do i', 'what should i', "i don't understand"
        ]
        
        # Count matches
        expert_count = sum(1 for term in expert_terms if term in message_lower)
        intermediate_count = sum(1 for term in intermediate_terms if term in message_lower)
        beginner_count = sum(1 for term in beginner_indicators if term in message_lower)
        
        # Update level (with some persistence)
        if expert_count >= 2:
            self.user_expertise_level = "expert"
        elif beginner_count >= 1:
            self.user_expertise_level = "beginner"
        elif intermediate_count >= 1 or expert_count >= 1:
            self.user_expertise_level = "intermediate"
        # Otherwise keep current level
    
    def _generate_suggestions(
        self,
        message: str,
        context: Optional[Dict[str, Any]]
    ) -> List[str]:
        """Generate quick action suggestions based on context."""
        suggestions = []
        
        if context and "current_cve" in context:
            suggestions.append(f"Explain how to fix {context['current_cve'].get('cve_id', 'this')}")
            suggestions.append("What's the risk if I don't fix this?")
            suggestions.append("Show me similar vulnerabilities")
        else:
            suggestions.append("What should I fix first?")
            suggestions.append("Show me my security score breakdown")
            suggestions.append("Generate an executive summary")
        
        return suggestions[:3]
    
    def _extract_sources(self, context: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
        """Extract relevant sources/links from context."""
        sources = []
        
        if context and "current_cve" in context:
            cve_id = context["current_cve"].get("cve_id", "")
            if cve_id:
                sources.append({
                    "title": f"NVD: {cve_id}",
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                })
        
        return sources
    
    def _fallback_response(
        self,
        message: str,
        context: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fallback responses when Gemini is unavailable."""
        message_lower = message.lower()
        
        # Pattern-based responses
        if "what should i fix" in message_lower or "fix first" in message_lower:
            response = """Based on the priority rankings, I recommend focusing on **Critical Priority** items first, followed by **High Priority**.

Here's a general approach:
1. **Critical Priority**: Fix immediately - these have the highest exploitation likelihood
2. **High Priority**: Address within 24-48 hours
3. **Moderate Priority**: Plan for your next sprint

Would you like me to explain any specific vulnerability?"""
        
        elif "security score" in message_lower:
            if context and "security_score" in context:
                score = context["security_score"]
                response = f"""Your current security score is **{score.get('score', 'Unknown')}/100** ({score.get('label', 'Unknown')}).

**Breakdown:**
- Critical: {score.get('breakdown', {}).get('critical', 0)}
- High: {score.get('breakdown', {}).get('high', 0)}
- Moderate: {score.get('breakdown', {}).get('moderate', 0)}
- Low: {score.get('breakdown', {}).get('low', 0)}

To improve your score, focus on resolving Critical and High priority items first."""
            else:
                response = "I don't have your security score data loaded. Please check the dashboard."
        
        elif context and "current_cve" in context:
            cve = context["current_cve"]
            response = f"""**{cve.get('cve_id', 'This vulnerability')}**

{cve.get('description', 'No description available.')[:300]}...

**Severity**: CVSS {cve.get('cvss_base_score', 'Unknown')}
**Patch Available**: {'Yes' if cve.get('has_patch') else 'No'}

For detailed remediation steps, I recommend:
1. Check the vendor advisory
2. Review the NVD page for more details
3. Test the patch in a staging environment first"""
        
        else:
            response = """I'm Shield, your AI security assistant! I can help you:

• **Understand vulnerabilities** - Explain what they mean and their risk
• **Prioritize fixes** - Tell you what to focus on first
• **Guide remediation** - Step-by-step instructions to fix issues
• **Answer questions** - General security guidance

What would you like help with?"""
        
        return {
            "success": True,
            "response": response,
            "expertise_level": self.user_expertise_level,
            "suggestions": self._generate_suggestions(message, context),
            "sources": self._extract_sources(context),
            "fallback": True
        }
    
    def reset_conversation(self):
        """Reset the conversation history."""
        self.conversation_history = []
        if self.model:
            self.chat_session = None
        self.user_expertise_level = "beginner"
    
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """Get the conversation history."""
        return self.conversation_history
