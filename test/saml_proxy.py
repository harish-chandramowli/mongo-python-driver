from pymongo import MongoClient

def test_conn():
    print("test")
    uri = "mongodb://host.local.10gen.cc:9900/admin"
    client = MongoClient(uri,
                         username="exkurfezsluTdll6a0h7",
                         password="noe",
                         authSource="admin",
                         authMechanism='SAML20',
                         ssl=True,
                         ssl_ca_certs="/Users/harishchandramowli/work/sunkworks/atlasproxy/main/ca.pem")
    db = client.test_database

    db.test.count_documents({'x': 1})


if __name__ == '__main__':
    test_conn()