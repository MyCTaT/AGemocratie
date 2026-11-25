import email.message
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'outils'))
from gmail_cleanup import new_message_id,remove_copy,CleanupQueue,MARKER,SUBJECT

SETTINGS={'SMTP_FROM':'agemocratie@gmail.com'}

class Mailbox:
    def __init__(self,marker=MARKER):
        self.message_id=new_message_id();self.calls=[];self.selected=None;self.changed_id=False
        message=email.message.EmailMessage()
        for key,value in {'Message-ID':self.message_id,'X-AGemocratie-Verification':marker,
                          'Subject':SUBJECT,'From':SETTINGS['SMTP_FROM'],'To':'test@etu.sorbonne-universite.fr'}.items():message[key]=value
        self.header=message.as_bytes();self.boxes={b'"Sent"':{b'10':(b'123',self.header)},b'"Trash"':{b'99':(b'456',b'Message-ID: <unrelated@example.org>\n')}}
    def list(self):return 'OK',[b'(\\Sent) "/" "Sent"',b'(\\Trash) "/" "Trash"']
    def select(self,folder):self.selected=folder;return 'OK',[b'1']
    def uid(self,command,*args):
        command=command.lower();self.calls.append((command,args))
        if command=='search':
            needle=('Message-ID: '+str(args[-1]).strip('"')).encode()
            ids=[uid for uid,(_,header) in self.boxes[self.selected].items() if needle in header]
            return 'OK',[b' '.join(ids)]
        if command=='fetch':
            gm_id,header=self.boxes[self.selected][args[0]]
            return 'OK',[(b'1 (X-GM-MSGID '+gm_id+b')',header)]
        if command=='copy':
            gm_id,header=self.boxes[self.selected].pop(args[0]);self.boxes[args[1]][b'20']=(b'999' if self.changed_id else gm_id,header)
            return 'OK',[b'copied']
        if command=='store':return 'OK',[b'stored']
        if command=='expunge':
            self.boxes[self.selected].pop(args[0],None);return 'OK',[b'1']
        raise AssertionError(command)

class CleanupTests(unittest.TestCase):
    def test_deletes_only_the_generated_copy_not_other_trash(self):
        client=Mailbox()
        self.assertTrue(remove_copy(client,SETTINGS,client.message_id))
        self.assertIn(b'99',client.boxes[b'"Trash"'])
        self.assertEqual([args[0] for command,args in client.calls if command=='expunge'],[b'20'])
    def test_no_deletion_for_legacy_unmarked_message_id(self):
        client=Mailbox()
        with self.assertRaises(ValueError):remove_copy(client,SETTINGS,'<legacy@example.org>')
        self.assertEqual(client.calls,[])
    def test_no_deletion_for_wrong_marker(self):
        client=Mailbox(marker='other')
        with self.assertRaises(RuntimeError):remove_copy(client,SETTINGS,client.message_id)
        self.assertFalse(any(cmd in ('copy','store','expunge') for cmd,_ in client.calls))
    def test_no_deletion_when_global_gmail_id_changes(self):
        client=Mailbox();client.changed_id=True
        with self.assertRaises(RuntimeError):remove_copy(client,SETTINGS,client.message_id)
        self.assertFalse(any(cmd in ('store','expunge') for cmd,_ in client.calls))
    def test_retries_message_already_moved_to_trash(self):
        client=Mailbox();client.boxes[b'"Trash"'][b'20']=client.boxes[b'"Sent"'].pop(b'10')
        self.assertTrue(remove_copy(client,SETTINGS,client.message_id))
        self.assertFalse(any(cmd=='copy' for cmd,_ in client.calls))
    def test_missing_sent_copy_remains_pending(self):
        client=Mailbox();client.boxes[b'"Sent"'].clear()
        self.assertFalse(remove_copy(client,SETTINGS,client.message_id))
        self.assertFalse(any(cmd in ('store','expunge') for cmd,_ in client.calls))
    def test_queue_survives_restart_without_address_or_otp(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'pending.json';queue=CleanupQueue(SETTINGS,path);message_id=new_message_id()
            queue.add(message_id)
            saved=json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(list(saved),[message_id]);self.assertIsInstance(saved[message_id],int)
            self.assertEqual(CleanupQueue(SETTINGS,path).pending,saved)

if __name__=='__main__':unittest.main()
