import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from agent.main import NodeAgent


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {'DONINO_PANEL_URL':'https://panel.example.com',
            'DONINO_NODE_TOKEN':'test-token', 'DONINO_NODE_STATE':self.tmp.name,
            'DONINO_XRAY':'/unused/xray'})
        self.env.start()
        self.agent = NodeAgent()
        self.running = Mock()
        self.running.poll.return_value = None
        self.agent.proc = self.running
        self.agent.revision = 'old-revision'

    def tearDown(self):
        self.agent.client.close()
        self.env.stop()
        self.tmp.cleanup()

    def desired(self):
        return {'revision':'new-revision', 'config':{'inbounds':[
            {'tag':'api','listen':'127.0.0.1','port':10085}]}}

    def test_remote_plain_http_refused(self):
        with patch.dict(os.environ, {'DONINO_PANEL_URL':'http://panel.example.com'}):
            with self.assertRaises(ValueError):NodeAgent()

    def test_public_stats_bind_refused(self):
        desired = self.desired()
        desired['config']['inbounds'][0]['listen'] = '0.0.0.0'
        with self.assertRaises(ValueError):self.agent.apply(desired)
        self.running.terminate.assert_not_called()

    def test_invalid_config_keeps_running_core(self):
        with patch('agent.main.subprocess.run', return_value=Mock(returncode=23)):
            with self.assertRaises(ValueError):self.agent.apply(self.desired())
        self.running.terminate.assert_not_called()
        self.assertEqual(self.agent.revision, 'old-revision')
        self.assertFalse((Path(self.tmp.name) / 'config.json').exists())

    def test_failed_final_report_keeps_running_core(self):
        with patch('agent.main.subprocess.run', return_value=Mock(returncode=0)), \
             patch.object(self.agent, 'report', side_effect=httpx.ConnectError('unavailable')):
            with self.assertRaises(httpx.ConnectError):self.agent.apply(self.desired())
        self.running.terminate.assert_not_called()
        self.assertEqual(self.agent.revision, 'old-revision')


if __name__ == '__main__':unittest.main()
