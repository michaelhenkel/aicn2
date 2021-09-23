until ls /etc/kubernetes/bootstrap-secrets/aggregator-ca.crt; do
  sleep 2
done
until ls /etc/kubernetes/bootstrap-secrets/kubeconfig; do
  sleep 2
done
cat <<EOF>/tmp/patch
data:
  requestheader-client-ca-file: |
$(while IFS= read -a line; do echo "    $line"; done < <(cat /etc/kubernetes/bootstrap-secrets/aggregator-ca.crt))
EOF
until KUBECONFIG=/etc/kubernetes/bootstrap-secrets/kubeconfig kubectl -n kube-system patch configmap extension-apiserver-authentication --patch-file /tmp/patch; do
  sleep 2
done
