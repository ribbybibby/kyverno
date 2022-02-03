package registryclient

import (
	"context"

	ecr "github.com/awslabs/amazon-ecr-credential-helper/ecr-login"
	"github.com/awslabs/amazon-ecr-credential-helper/ecr-login/api"
	"github.com/chrismellard/docker-credential-acr-env/pkg/credhelper"
	"github.com/google/go-containerregistry/pkg/authn"
	kauth "github.com/google/go-containerregistry/pkg/authn/kubernetes"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

var (
	Secrets []string

	kubeClient       kubernetes.Interface
	kyvernoNamespace string

	amazonKeychain  authn.Keychain = authn.NewKeychainFromHelper(ecr.ECRHelper{ClientFactory: api.DefaultClientFactory{}})
	azureKeychain   authn.Keychain = authn.NewKeychainFromHelper(credhelper.NewACRCredentialsHelper())
	defaultKeychain authn.Keychain = authn.NewMultiKeychain(
		authn.DefaultKeychain,
		google.Keychain,
		amazonKeychain,
		azureKeychain,
	)
	DefaultKeychain authn.Keychain = defaultKeychain
)

// Initialize loads the image pull secrets and initializes the default auth method for container registry API calls
func Initialize(client kubernetes.Interface, namespace string, imagePullSecrets []string) error {
	kubeClient = client
	kyvernoNamespace = namespace
	Secrets = imagePullSecrets

	ctx := context.Background()

	var pullSecrets []corev1.Secret
	for _, name := range imagePullSecrets {
		ps, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		pullSecrets = append(pullSecrets, *ps)
	}

	kc, err := kauth.NewFromPullSecrets(ctx, pullSecrets)
	if err != nil {
		return errors.Wrap(err, "failed to initialize registry keychain")
	}

	DefaultKeychain = authn.NewMultiKeychain(
		defaultKeychain,
		kc,
	)

	return nil
}

// UpdateKeychain reinitializes the image pull secrets and default auth method for container registry API calls
func UpdateKeychain() error {
	var err = Initialize(kubeClient, kyvernoNamespace, Secrets)
	if err != nil {
		return err
	}
	return nil
}
