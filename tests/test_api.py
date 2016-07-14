import nofussbm
import unittest
import flask
import flask_pymongo

import datetime
import json
import hmac
from hashlib import sha1
from base64 import b64encode
from bson.objectid import ObjectId

class NofussbmTestCase(unittest.TestCase):

    def setUp(self):
        self.client = nofussbm.app.test_client()
        self.email = 'nofussbm@sink.sendgrid.net'
        self.SECRET_KEY = nofussbm.Config.SECRET_KEY
        self.key = b64encode('{0}:{1}'.format(self.email, hmac.new(self.SECRET_KEY, self.email, sha1).hexdigest()))


    def tearDown(self):
        with nofussbm.app.app_context():
            nofussbm.mongo.cx.drop_database(nofussbm.app.config['MONGO_DBNAME'])


    def isJson(self, myjson):
        try:
            json.loads(myjson)
        except ValueError:
            return False
        return True


    def seedMongo(self):
        with open('tests/seed.json', 'r') as f:
            seed = json.load(f)
        self.seed_ids = []
        for pos, bm in enumerate(seed):
            bm['email'] = self.email
            bm['date-added'] = bm['date-modified'] = datetime.datetime.utcnow()
            rv = nofussbm.mongo.db.bookmarks.insert_one(bm)
            self.seed_ids.append(rv.inserted_id)


    def testMongo(self):
        self.assertIsInstance(nofussbm.mongo, flask_pymongo.PyMongo)
        with nofussbm.app.app_context():
            self.assertIsInstance(nofussbm.mongo.db, flask_pymongo.wrappers.Database)
            self.assertEqual(nofussbm.app.config['MONGO_DBNAME'], 'nofussbm-test')


    @unittest.skip("until others are fixed")
    def testSendkey(self):
        rv = self.client.post('/api/v1/sendkey', data=dict(email=self.email))
        self.assertEqual(rv.get_data(), '')
        self.assertEqual(rv.status_code, 200)


    def testPost(self):
        rv = self.client.post('/api/v1/', data=json.dumps([dict(
            title='Google.com',
            url='http://google.com',
            tags='google,search engine'
        )]), headers={'X-Nofussbm-Key': self.key},
            content_type = 'application/json')
        rvdata = rv.get_data()
        self.assertIsInstance(rvdata, str)
        self.assertTrue(self.isJson(rvdata))
        self.assertIn('error', json.loads(rvdata))
        self.assertIn('added', json.loads(rvdata))


    def testGet(self):
        with nofussbm.app.app_context():
            self.seedMongo()
        rv = self.client.get('/api/v1/', headers={'X-Nofussbm-Key': self.key})
        rvdata = rv.get_data()
        self.assertIsInstance(rvdata, str)
        self.assertTrue(self.isJson(rvdata))
        self.assertRegexpMatches(rv.headers.get('Content-Range'), r'bookmarks \d+-\d+/\d+')
        self.assertRegexpMatches(rv.headers.get('Accept-Ranges'), r'bookmarks')
        # with nofussbm.app.test_request_context('/api/v1/',
        #                                        headers={'X-Nofussbm-Key': self.key,
        #                                                 'X-Nofussbm-Query': 'id=' + str(self.seed_ids[0]) +
        #                                                                     '&title=Github&tags=github,public repositories'}):
        #     self.assertEqual(flask.request.headers['X-Nofussbm-Query'], u'id=' + str(self.seed_ids[0]) +
        #                                                                 u'&title=Github&tags=github,public repositories')
        # rvquery = self.client.get('/api/v1/', headers={'X-Nofussbm-Key': self.key,
        #                                                'X-Nofussbm-Query': 'title=Github&tags=github,public repositories&'
        #                                                                    'id=' + str(self.seed_ids[0])})
        # rvquerydata = rvquery.get_data()
        # self.assertIsInstance(rvquerydata, str)
        # self.assertTrue(self.isJson(rvquerydata))
        # rvqueryjson = json.loads(rvquerydata)
        # for key in set(['title', 'url', 'id', 'tags', 'date-added', 'date-modified']):
        #     self.assertIn(key, rvqueryjson)
        # self.assertEqual(rvqueryjson['title'], 'Github')
        # self.assertEqual(rvqueryjson['url'], 'https://github.com')
        # self.assertEqual(rvqueryjson['tags'], 'github,git,public repositories')


    def testQueryFromDict(self):
        with nofussbm.app.app_context():
            self.seedMongo()
        dct = {
            'id': ObjectId(self.seed_ids[0]),
            'title': u'Github',
            'tags': u'github,git'
        }
        check = {'_id': ObjectId(self.seed_ids[0]),
                 'title': {'$options': 'i', '$regex': u'Github'},
                 'email': self.email,
                 'tags': {'$all': [u'github', u'git']}}
        query = nofussbm.query_from_dict(self.email, dct)
        self.assertEqual(query, check)


    def testPut(self):
        with nofussbm.app.app_context():
            self.seedMongo()
        rv = self.client.put('/api/v1/', data=json.dumps([dict(
            id=str(self.seed_ids[0]),
            title='Github',
            url='https://github.com',
            tags='github'
        )]), headers={'X-Nofussbm-Key': self.key},
             content_type='application/json')
        rvdata = rv.get_data()
        self.assertIsInstance(rvdata, str)
        self.assertTrue(self.isJson(rvdata))
        self.assertIn('error', json.loads(rvdata))
        self.assertIn('updated', json.loads(rvdata))
        self.assertIn('ignored', json.loads(rvdata))
        check = self.client.get('/api/v1/' + str(self.seed_ids[0]), headers={'X-Nofussbm-Key': self.key})
        checkdata = check.get_data()
        self.assertIsInstance(checkdata, str)
        self.assertTrue(self.isJson(checkdata))
        checkjson = json.loads(checkdata)
        self.assertItemsEqual(checkjson[0]['tags'], ['github'])


    def testDelete(self):
        with nofussbm.app.app_context():
            self.seedMongo()
        rv = self.client.delete('/api/v1/', data=json.dumps([dict(
            id=str(self.seed_ids[0]),
            title='Github',
            url='https://github.com',
            tags='github'
        )]), headers={'X-Nofussbm-Key': self.key},
             content_type='application/json')
        rvdata = rv.get_data()
        self.assertIsInstance(rvdata, str)
        self.assertTrue(self.isJson(rvdata))
        self.assertIn('error', json.loads(rvdata))
        self.assertIn('deleted', json.loads(rvdata))
        self.assertIn('ignored', json.loads(rvdata))
        check = self.client.get('/api/v1/' + str(self.seed_ids[0]), headers={'X-Nofussbm-Key': self.key})
        checkdata = check.get_data()
        self.assertIsInstance(checkdata, str)
        self.assertTrue(self.isJson(checkdata))
        checkjson = json.loads(checkdata)
        self.assertEqual(checkjson, [None])


    def testStats(self):
        with nofussbm.app.app_context():
            self.seedMongo()
        rv = self.client.get('/api/v1/stats')
        rvdata = rv.get_data()
        self.assertIsInstance(rvdata, str)
        self.assertTrue(self.isJson(rvdata))
        rvjson = json.loads(rvdata)
        self.assertIn('users', rvjson)
        self.assertEqual([u'users'], rvjson.keys())
        self.assertEqual(1, len(rvjson['users']))
        self.assertItemsEqual([u'email',u'count'], rvjson['users'][0].keys())


if __name__ == '__main__':
    unittest.main()