import boto
import boto.utils
from boto.ec2.elb import ELBConnection
from boto.ec2.regioninfo import RegionInfo
from boto.ec2.elb.loadbalancer import LoadBalancer
from boto.ec2.cloudwatch import CloudWatchConnection
from boto.iam.connection import IAMConnection
import servo.hostname_cache as hostname_cache
import time
import M2Crypto
from collections import Iterable

def connect_euare(host_name=None, port=80, path="services/Euare", aws_access_key_id=None, aws_secret_access_key=None, security_token=None, **kwargs):
    return EucaEuareConnection(host=host_name, port=port, path=path, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, security_token=security_token, **kwargs)

def connect_elb(host_name=None, port=80, cluster=None, path="services/LoadBalancing", aws_access_key_id=None, aws_secret_access_key=None, security_token = None, **kwargs):
    region=RegionInfo(name=cluster, endpoint=host_name)
    
    return EucaELBConnection(region=region, port=port, path=path, aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key, security_token=security_token,  **kwargs)

class StatefulInstance(object):
    def __init__(self, instance_id=None, state=None):
        self.instance_id = instance_id
        self.state = state

    def __repr__(self):
        return '%s:%s' % (self.instance_id, self.state)

    def __str__(self):
        return self.__repr__()

    def startElement(self, name, attrs, connection):
        return None
 
    def endElement(self, name, value, connection):
        if name == 'InstanceId':
            self.instance_id = value
        elif name == 'InstanceState':
            self.instance_state = value
        else:
            setattr(self, name, value)

class EucaEuareConnection(IAMConnection):
    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, proxy=None, proxy_port=None,
                 proxy_user=None, proxy_pass=None, host=None, debug=0, 
                 https_connection_factory=None, path='/', security_token=None, validate_certs=True):
        """
        Euca-specific extension to boto's IAM connection. 
        """
        IAMConnection.__init__(self, aws_access_key_id,
                            aws_secret_access_key,
                            is_secure, port, proxy,
                            proxy_port, proxy_user, proxy_pass,
                            host, debug, https_connection_factory,
                            path, security_token,
                            validate_certs=validate_certs)

    def download_server_certificate(self, cert, pk, auth_signature, cert_arn):
        """
        Download server certificate identified with 'cert_arn'. del_certificate and auth_signature
        represent that the client is authorized to download the certificate

        :type cert_arn: string
        :param cert_arn: The ARN of the server ceritifcate to download
 
        :type delegation_certificate: string
        :param delegation_certificate: The certificate to show that this client is delegated to download the user's server certificate

        :type auth_signature: string
        :param auth_signature: The signature by Euare as a proof that the bearer of delegation_certificate is authorized to download server certificate
 
        """
        timestamp = boto.utils.get_ts()
        msg= cert_arn+"&"+timestamp
        rsa = M2Crypto.RSA.load_key_string(pk)
        msg_digest = M2Crypto.EVP.MessageDigest('sha256')
        msg_digest.update(msg)
        sig = rsa.sign(msg_digest.digest(),'sha256')
        sig = sig.encode('base64')
        cert = cert.encode('base64')

        print "msg: %s, signature: %s" % (msg,sig)
        params = {'CertificateArn': cert_arn,
                  'DelegationCertificate': cert,
                  'AuthSignature':auth_signature,
                  'Timestamp':timestamp,
                  'Signature':sig} 
        return self.get_status('DownloadServerCertificate', params)

 
class EucaELBConnection(ELBConnection):
    def __init__(self, aws_access_key_id=None, aws_secret_access_key=None,
                 is_secure=False, port=None, proxy=None, proxy_port=None,
                 proxy_user=None, proxy_pass=None, debug=0,
                 https_connection_factory=None, region=None, path='/',
                 security_token=None, validate_certs=True):
        """
        Init method to create a new connection to EC2 Load Balancing Service.

        note:: The region argument is overridden by the region specified in
            the boto configuration file.
        """
        if not region:
            region = RegionInfo(self, self.DefaultRegionName,
                                self.DefaultRegionEndpoint)
        self.region = region
        self.cw_con = CloudWatchConnection(aws_access_key_id,
                                    aws_secret_access_key,
                                    is_secure, port, proxy, proxy_port,
                                    proxy_user, proxy_pass, debug,
                                    https_connection_factory, region, path,
                                    security_token,
                                    validate_certs=validate_certs)
        ELBConnection.__init__(self, aws_access_key_id,
                                    aws_secret_access_key,
                                    is_secure, port, proxy, proxy_port,
                                    proxy_user, proxy_pass, debug,
                                    https_connection_factory, region, path,
                                    security_token,
                                    validate_certs=validate_certs)

    def put_cw_metric(self, servo_instance_id, metric):
        params = {'InstanceId':servo_instance_id}
        namespace = 'Servo'
        name = ['Latency','RequestCount','HTTPCode_ELB_4XX','HTTPCode_ELB_5XX','HTTPCode_Backend_2XX','HTTPCode_Backend_3XX','HTTPCode_Backend_4XX','HTTPCode_Backend_5XX']
        value = [metric.Latency, metric.RequestCount, metric.HTTPCode_ELB_4XX, metric.HTTPCode_ELB_5XX, metric.HTTPCode_Backend_2XX, metric.HTTPCode_Backend_3XX, metric.HTTPCode_Backend_4XX, metric.HTTPCode_Backend_5XX]
        unit = ['Milliseconds','Count','Count','Count','Count','Count','Count','Count']
        self.cw_con.build_put_params(params, name, value=value,timestamp=None, unit=unit, dimensions=None, statistics=None)

        return self.get_status('PutServoStates', params)

    def put_instance_health(self, servo_instance_id, instances):
        """
        Test the internal loadbalancer vms
        """
        params = {'InstanceId':servo_instance_id}
        if instances:
            self.build_list_params(params, instances, 'Instances.member.%d.InstanceId')
        return self.get_status('PutServoStates', params)

    def get_servo_load_balancers(self, servo_instance_id):
        #marker = "servo:%s" % servo_instance_id
        params = {"InstanceId": servo_instance_id}
        lbs = self.get_list('DescribeLoadBalancersByServo', params,
                             [('member', LoadBalancer)])

        for lb in lbs:
            instances = []
            if lb.instances is not None and isinstance(lb.instances, Iterable):
                for inst in lb.instances:
                    inst_id=str(inst.id) 
                    if inst_id.find(':')>=0:
                        token = inst_id.split(':')
                        inst_id=token[0]
                        ipaddr=token[1]
                        hostname_cache.register(inst_id, ipaddr)
                        inst.id = inst_id
 
        return lbs
