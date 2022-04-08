IMPORT github.com/Konubinix/Earthfile AS e

test:
    FROM earthly/dind:alpine
	RUN apk add --update git
	DO e+USE_USER
 	RUN wget -O - https://clk-project.org/install.sh | env CLK_EXTENSIONS=k8s sh
	USER root
	COPY hello hello
	WITH DOCKER
		RUN clk k8s flow
		&& helm upgrade --install hello hello \
		&& while ! kubectl get pod | grep -q Running;do echo wait for pod;sleep 2;done \
		&& echo "A pod is running!"
	END
