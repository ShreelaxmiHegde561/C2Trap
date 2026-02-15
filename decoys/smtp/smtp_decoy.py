"""
C2Trap SMTP Honeypot
Captures email-based C2 communications
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from email import message_from_bytes
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, Envelope, Session

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('smtp_decoy')

LOG_PATH = os.environ.get('LOG_PATH', '/app/logs/analysis_queue.jsonl')


def log_event(event_type: str, data: dict) -> None:
    """Write event to analysis queue"""
    event = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'source': 'smtp_decoy',
        'event_type': event_type,
        'data': data
    }
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, 'a') as f:
            f.write(json.dumps(event) + '\n')
    except Exception as e:
        logger.error(f"Failed to write log: {e}")


class C2TrapHandler:
    """SMTP handler that accepts and logs all emails"""
    
    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        """Accept any recipient"""
        envelope.rcpt_tos.append(address)
        log_event('smtp_rcpt', {
            'peer': str(session.peer),
            'recipient': address
        })
        return '250 OK'
    
    async def handle_MAIL(self, server, session, envelope, address, mail_options):
        """Accept any sender"""
        envelope.mail_from = address
        log_event('smtp_mail_from', {
            'peer': str(session.peer),
            'sender': address,
            'mitre_technique': 'T1071.003'
        })
        logger.info(f"[SMTP] Mail from {address} (peer: {session.peer})")
        return '250 OK'
    
    async def handle_DATA(self, server, session, envelope):
        """Accept and log email content"""
        try:
            # Parse email
            msg = message_from_bytes(envelope.content)
            
            # Extract key fields
            email_data = {
                'peer': str(session.peer),
                'mail_from': envelope.mail_from,
                'rcpt_tos': envelope.rcpt_tos,
                'subject': msg.get('Subject', ''),
                'from': msg.get('From', ''),
                'to': msg.get('To', ''),
                'date': msg.get('Date', ''),
                'content_type': msg.get_content_type(),
                'size': len(envelope.content),
                'mitre_technique': 'T1071.003'
            }
            
            # Check for attachments
            attachments = []
            if msg.is_multipart():
                for part in msg.walk():
                    filename = part.get_filename()
                    if filename:
                        attachments.append({
                            'filename': filename,
                            'content_type': part.get_content_type(),
                            'size': len(part.get_payload(decode=True) or b'')
                        })
            
            email_data['attachments'] = attachments
            email_data['has_attachments'] = len(attachments) > 0
            
            log_event('smtp_message', email_data)
            
            logger.info(f"[SMTP] Message from {envelope.mail_from} to {envelope.rcpt_tos}")
            if attachments:
                logger.warning(f"[SMTP] Message has {len(attachments)} attachment(s)")
            
        except Exception as e:
            logger.error(f"Error parsing email: {e}")
            log_event('smtp_parse_error', {
                'peer': str(session.peer),
                'error': str(e)
            })
        
        return '250 Message accepted for delivery'
    
    async def handle_EHLO(self, server, session, envelope, hostname, responses):
        """Handle EHLO with extended capabilities"""
        session.host_name = hostname
        log_event('smtp_ehlo', {
            'peer': str(session.peer),
            'hostname': hostname
        })
        return responses
    
    async def handle_HELO(self, server, session, envelope, hostname):
        """Handle HELO"""
        session.host_name = hostname
        log_event('smtp_helo', {
            'peer': str(session.peer),
            'hostname': hostname
        })
        return '250 OK'


async def main():
    port = int(os.environ.get('SMTP_PORT', 25))
    
    handler = C2TrapHandler()
    controller = Controller(
        handler,
        hostname='0.0.0.0',
        port=port,
        ready_timeout=30
    )
    
    logger.info(f"Starting SMTP Decoy on port {port}")
    
    controller.start()
    
    try:
        while True:
            await asyncio.sleep(3600)
    except KeyboardInterrupt:
        logger.info("Shutting down SMTP Decoy")
    finally:
        controller.stop()


if __name__ == '__main__':
    asyncio.run(main())
