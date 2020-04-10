#include <libssh/libssh.h>
#include <stdlib.h>
#include <stdio.h> 
#include <string.h>

char *password = "cisco";
char *enable_pass = "cisco123\n";
char *enable = "enable\n";
char buffer[2560];
char pass_buffer[256];
char *cmd = "show ssh\n";


  
int send_command(ssh_session session){

  int rc;

  ssh_channel channel;

  channel = ssh_channel_new(session);
  if (channel == NULL) return SSH_ERROR;
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }

  int nbytes;

  rc = ssh_channel_request_shell(channel);
  if (rc != SSH_OK) {
    printf("Error getting a shell\n");
    return rc;
  }

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes>0) {
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }

  nbytes = ssh_channel_write(channel, enable, strlen(enable));
  printf("enable sent\n");

  nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
  while (nbytes>0) {
    nbytes = ssh_channel_read(channel, pass_buffer, sizeof(pass_buffer), 0);
  }

  printf("Server says %s\n", pass_buffer);
  fprintf(stderr, "Sending the following command to server: %s\n", cmd);
  
  sleep(2);
  ssh_channel_write(channel, enable_pass, strlen(enable_pass));

  /*    if (!nbytes) {
        fprintf(stderr, "ERROR in channel write\n");
        return SSH_ERROR;
      }
  */
  ssh_channel_write(channel, cmd, strlen(cmd));

  memset(buffer, 0, sizeof(buffer));

  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes>0) {
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }

  printf("Server responds with:\n%s\n", buffer);



    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return SSH_OK;
}


int main() {

  ssh_session my_ssh_session;
  int rc;
  // Open session and set options
  my_ssh_session = ssh_new();
  if (my_ssh_session == NULL)
    exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "10.0.2.18");
  // Connect to server
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting to host: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_free(my_ssh_session);
    exit(-1);
  }
  // Authenticate ourselves
  rc = ssh_options_set(my_ssh_session, SSH_OPTIONS_USER, "cisco");
  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }

  send_command(my_ssh_session);

  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
}

