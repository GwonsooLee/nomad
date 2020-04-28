package fingerprint

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	log "github.com/hashicorp/go-hclog"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
	"github.com/hashicorp/nomad/nomad/structs"
)

const (
	// AwsMetadataTimeout is the timeout used when contacting the AWS metadata
	// services.
	AwsMetadataTimeout = 2 * time.Second

	// deferProcSpeed notes that a 0 Mhz speed will be replaced by the value
	// detected by go-psutil in the CPU fingerprinter in the event the CPU
	// properties of this ec2 instance are non-determinable.
	deferProcSpeed = 0
)

// map of instance type to approximate speed, in Mbits/s
// Estimates from http://stackoverflow.com/a/35806587
// This data is meant for a loose approximation
var ec2NetSpeedTable = map[*regexp.Regexp]int{
	regexp.MustCompile("t2.nano"):      30,
	regexp.MustCompile("t2.micro"):     70,
	regexp.MustCompile("t2.small"):     125,
	regexp.MustCompile("t2.medium"):    300,
	regexp.MustCompile("m3.medium"):    400,
	regexp.MustCompile("c4.8xlarge"):   4000,
	regexp.MustCompile("x1.16xlarge"):  5000,
	regexp.MustCompile(`.*\.large`):    500,
	regexp.MustCompile(`.*\.xlarge`):   750,
	regexp.MustCompile(`.*\.2xlarge`):  1000,
	regexp.MustCompile(`.*\.4xlarge`):  2000,
	regexp.MustCompile(`.*\.8xlarge`):  10000,
	regexp.MustCompile(`.*\.10xlarge`): 10000,
	regexp.MustCompile(`.*\.16xlarge`): 10000,
	regexp.MustCompile(`.*\.32xlarge`): 10000,
}

// map of instance type to documented CPU speed, in MHz.
//
// Most values are taken from https://aws.amazon.com/ec2/instance-types/.
// Values for a1 & m6g (Graviton) are taken from https://en.wikichip.org/wiki/annapurna_labs/alpine/al73400
// Values for inf1 are taken from launching a inf1.xlarge and looking at /proc/cpuinfo
//
// In a few cases, AWS has upgraded the generation of CPU while keeping the same
// instance designation. Since it is possible to launch on the lower performance
// CPU, that one is used as the spec for the instance type.
var ec2ProcSpeedTable = map[*regexp.Regexp]float64{
	// General Purpose
	regexp.MustCompile(`a1\..*`):                              2_300, // Custom built AWS Graviton
	regexp.MustCompile(`t3\..*`):                              2_500, // 2.5 GHz Intel Scalable
	regexp.MustCompile(`t3a\..*`):                             2_500, // 2.5 GHz AMD EPYC 7000 series
	regexp.MustCompile(`t2\.(nano)|(micro)|(small)|(medium)`): 3_300, // 3.3 GHz Intel Scalable
	regexp.MustCompile(`t2\.(large)|(xlarge)|(2xlarge)`):      3_000, // 3.0 GHz Intel Scalable
	regexp.MustCompile(`m6g\..*`):                             2_300, // Custom built AWS Graviton
	regexp.MustCompile(`m5d?\..*`):                            3_100, // 3.1 GHz Intel Xeon Platinum
	regexp.MustCompile(`m5ad?\..*`):                           2_500, // 2.5 GHz AMD EPYC 7000 series
	regexp.MustCompile(`m5d?n\..*`):                           3_100, // 3.1 GHz Intel Xeon Scalable
	regexp.MustCompile(`m4\..*`):                              2_300, // 2.3 GHz Intel Xeon® E5-2686 v4

	// Compute Optimized
	regexp.MustCompile(`c5d?\.(12xlarge)|(24xlarge)|(metal)`): 3_600, // 3.6 GHz Intel Xeon Scalable
	regexp.MustCompile(`c5d?\..*`):                            3_400, // 3.4 GHz Intel Xeon Platinum 8000
	regexp.MustCompile(`c5n\..*`):                             3_000, // 3.0 GHz Intel Xeon Platinum
	regexp.MustCompile(`c4\..*`):                              2_900, // 2.9 GHz Intel Xeon E5-2666 v3

	// Memory Optimized
	regexp.MustCompile(`r5d?\..*`):                 3_100, // 3.1 GHz Intel Xeon Platinum
	regexp.MustCompile(`r5ad\..*`):                 2_500, // 2.5 GHz AMD EPYC 7000 series
	regexp.MustCompile(`r5d?n\..*`):                3_100, // 3.1 GHz Intel Xeon Scalable
	regexp.MustCompile(`r4\..*`):                   2_300, // 2.3 GHz Intel Xeon E5-2686 v4
	regexp.MustCompile(`x1e\..*`):                  2_300, // 2.3 GHz Intel Xeon E7-8880 v3
	regexp.MustCompile(`x1\..*`):                   2_300, // 2.3 GHz Intel Xeon E7-8880 v3
	regexp.MustCompile(`u-(6)|(9)|(12)tb1\.metal`): 2_100, // 2.1 GHz Intel Xeon Platinum 8176M
	regexp.MustCompile(`u-(18)|(24)tb1\.metal`):    2_700, // 2.7 GHz Intel Xeon Scalable
	regexp.MustCompile(`z1d\..*`):                  4_000, // 4.0 GHz Custom Intel Xeon Scalable

	// Accelerated Computing
	regexp.MustCompile(`p3\.(2xlarge)|(8xlarge)|(16xlarge)`): 2_300, // 2.3 GHz Intel Xeon E5-2686 v4
	regexp.MustCompile(`p3\.24xlarge`):                       2_500, // 2.5 GHz Intel Xeon P-8175M
	regexp.MustCompile(`p2\..*`):                             2_300, // 2.3 GHz Intel Xeon E5-2686 v4 Processor
	regexp.MustCompile(`inf1\..*`):                           3_000, // 3.0 GHz Intel Xeon Platinum 8275CL
	regexp.MustCompile(`g4dn\..*`):                           2_500, // 2.5 GHz Cascade Lake 24C
	regexp.MustCompile(`g3s?\..*`):                           2_300, // 2.3 GHz Intel Xeon E5-2686 v4
	regexp.MustCompile(`f1\..*`):                             2_300, // 2.3 GHz Intel Xeon E5-2686 v4

	// Storage Optimized
	regexp.MustCompile(`i3\..*`):   2_300, // 2.3 GHz Intel Xeon E5 2686 v4
	regexp.MustCompile(`i3en\..*`): 3_100, // 3.1 GHz Intel Xeon Scalable
	regexp.MustCompile(`d2\..*`):   2_400, // 2.4 GHz Intel Xeon E5-2676 v3
	regexp.MustCompile(`h1\..*`):   2_300, // 2.3 GHz Intel Xeon E5 2686 v4
}

// EnvAWSFingerprint is used to fingerprint AWS metadata
type EnvAWSFingerprint struct {
	StaticFingerprinter

	// endpoint for EC2 metadata as expected by AWS SDK
	endpoint string

	logger log.Logger
}

// NewEnvAWSFingerprint is used to create a fingerprint from AWS metadata
func NewEnvAWSFingerprint(logger log.Logger) Fingerprint {
	f := &EnvAWSFingerprint{
		logger:   logger.Named("env_aws"),
		endpoint: strings.TrimSuffix(os.Getenv("AWS_ENV_URL"), "/meta-data/"),
	}
	return f
}

func (f *EnvAWSFingerprint) Fingerprint(request *FingerprintRequest, response *FingerprintResponse) error {
	cfg := request.Config

	timeout := AwsMetadataTimeout

	// Check if we should tighten the timeout
	if cfg.ReadBoolDefault(TightenNetworkTimeoutsConfig, false) {
		timeout = 1 * time.Millisecond
	}

	ec2meta, err := ec2MetaClient(f.endpoint, timeout)
	if err != nil {
		return fmt.Errorf("failed to setup ec2Metadata client: %v", err)
	}

	if !isAWS(ec2meta) {
		return nil
	}

	// Keys and whether they should be namespaced as unique. Any key whose value
	// uniquely identifies a node, such as ip, should be marked as unique. When
	// marked as unique, the key isn't included in the computed node class.
	keys := map[string]bool{
		"ami-id":                      false,
		"hostname":                    true,
		"instance-id":                 true,
		"instance-type":               false,
		"local-hostname":              true,
		"local-ipv4":                  true,
		"public-hostname":             true,
		"public-ipv4":                 true,
		"placement/availability-zone": false,
	}

	for k, unique := range keys {
		resp, err := ec2meta.GetMetadata(k)
		v := strings.TrimSpace(resp)
		if v == "" {
			f.logger.Debug("read an empty value", "attribute", k)
			continue
		} else if awsErr, ok := err.(awserr.RequestFailure); ok {
			f.logger.Debug("could not read attribute value", "attribute", k, "error", awsErr)
			continue
		} else if awsErr, ok := err.(awserr.Error); ok {
			// if it's a URL error, assume we're not in an AWS environment
			// TODO: better way to detect AWS? Check xen virtualization?
			if _, ok := awsErr.OrigErr().(*url.Error); ok {
				return nil
			}

			// not sure what other errors it would return
			return err
		}

		// assume we want blank entries
		key := "platform.aws." + strings.Replace(k, "/", ".", -1)
		if unique {
			key = structs.UniqueNamespace(key)
		}

		response.AddAttribute(key, v)
	}

	// newNetwork is populated and added to the Nodes resources
	var newNetwork *structs.NetworkResource

	// copy over network specific information
	if val, ok := response.Attributes["unique.platform.aws.local-ipv4"]; ok && val != "" {
		response.AddAttribute("unique.network.ip-address", val)

		newNetwork = &structs.NetworkResource{
			Device: "eth0",
			IP:     val,
			CIDR:   val + "/32",
			MBits:  f.throughput(request, ec2meta, val),
		}

		response.NodeResources = &structs.NodeResources{
			Networks: []*structs.NetworkResource{newNetwork},
		}
	}

	// copy over CPU speed information
	//
	// todo: also need num cores, cpu name, total ticks (see fingerprint.cpu)
	if mhz := f.frequencyMHz(ec2meta); mhz != deferProcSpeed {
		response.AddAttribute("cpu.frequency", fmt.Sprintf("%.0f", mhz))
		f.logger.Debug("detected ec2 cpu frequency", "MHz", log.Fmt("%.0f", mhz))
	}

	// populate Links
	response.AddLink("aws.ec2", fmt.Sprintf("%s.%s",
		response.Attributes["platform.aws.placement.availability-zone"],
		response.Attributes["unique.platform.aws.instance-id"]))
	response.Detected = true

	return nil
}

func (f *EnvAWSFingerprint) instanceType(ec2meta *ec2metadata.EC2Metadata) (string, error) {
	response, err := ec2meta.GetMetadata("instance-type")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(response), nil
}

func (f *EnvAWSFingerprint) frequencyMHz(ec2meta *ec2metadata.EC2Metadata) float64 {
	instanceType, err := f.instanceType(ec2meta)
	if err != nil {
		f.logger.Error("error reading instance-type", "error", err)
		return deferProcSpeed
	}
	for regex, mhz := range ec2ProcSpeedTable {
		if regex.MatchString(instanceType) {
			return mhz
		}
	}
	return deferProcSpeed
}

func (f *EnvAWSFingerprint) throughput(request *FingerprintRequest, ec2meta *ec2metadata.EC2Metadata, ip string) int {
	throughput := request.Config.NetworkSpeed
	if throughput != 0 {
		return throughput
	}

	throughput = f.linkSpeed(ec2meta)
	if throughput != 0 {
		return throughput
	}

	if request.Node.Resources != nil && len(request.Node.Resources.Networks) > 0 {
		for _, n := range request.Node.Resources.Networks {
			if n.IP == ip {
				return n.MBits
			}
		}
	}

	return defaultNetworkSpeed
}

// EnvAWSFingerprint uses lookup table to approximate network speeds
func (f *EnvAWSFingerprint) linkSpeed(ec2meta *ec2metadata.EC2Metadata) int {
	instanceType, err := f.instanceType(ec2meta)
	if err != nil {
		f.logger.Error("error reading instance-type", "error", err)
		return 0
	}

	netSpeed := 0
	for reg, speed := range ec2NetSpeedTable {
		if reg.MatchString(instanceType) {
			netSpeed = speed
			break
		}
	}

	return netSpeed
}

func ec2MetaClient(endpoint string, timeout time.Duration) (*ec2metadata.EC2Metadata, error) {
	client := &http.Client{
		Timeout:   timeout,
		Transport: cleanhttp.DefaultTransport(),
	}

	c := aws.NewConfig().WithHTTPClient(client).WithMaxRetries(0)
	if endpoint != "" {
		c = c.WithEndpoint(endpoint)
	}

	sess, err := session.NewSession(c)
	if err != nil {
		return nil, err
	}
	return ec2metadata.New(sess, c), nil
}

func isAWS(ec2meta *ec2metadata.EC2Metadata) bool {
	v, err := ec2meta.GetMetadata("ami-id")
	v = strings.TrimSpace(v)
	return err == nil && v != ""
}
