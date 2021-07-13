package io.opensaber.registry.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.opensaber.registry.exception.DuplicateRecordException;
import io.opensaber.registry.exception.EntityCreationException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.util.ResourceUtils;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import javax.annotation.PostConstruct;
import javax.ws.rs.ClientErrorException;
import javax.ws.rs.core.Response;


@Component
public class KeycloakAdminUtil {
    private static final Logger logger = LoggerFactory.getLogger(KeycloakAdminUtil.class);


    private String realm;
    private String adminClientSecret;
    private String adminClientId;
    private String authURL;
    private final Keycloak keycloak;
    private DefinitionsManager definitionsManager;
    private String roleBaseFilePath;
    private String groupDefinitionDir;


    @NoArgsConstructor
    @Getter
    static
    class RoleDefinition {
        private String name;
        private String description;
    }

    @NoArgsConstructor
    @Getter
    static
    class GroupDefinition {
        private String name;
        private List<String> realmRoles;
    }

    @Autowired
    public KeycloakAdminUtil(
            @Value("${keycloak.realm}") String realm,
            @Value("${keycloak-admin.client-secret}") String adminClientSecret,
            @Value("${keycloak-admin.client-id}") String adminClientId,
            @Value("${keycloak.auth-server-url}") String authURL,
            @Value("${groups.roles.base-file}") String roleBaseFilePath,
            @Value("${groups.definition-dir}") String groupDefinitionDir,
            @Autowired DefinitionsManager definitionsManager) {
        this.realm = realm;
        this.adminClientSecret = adminClientSecret;
        this.adminClientId = adminClientId;
        this.authURL = authURL;
        this.keycloak = buildKeycloak();
        this.roleBaseFilePath = roleBaseFilePath;
        this.groupDefinitionDir = groupDefinitionDir;
        this.definitionsManager = definitionsManager;
    }

    @PostConstruct
    void loadEntityRolesAndGroups() throws Exception {
        ObjectMapper m = new ObjectMapper();
        List<RoleDefinition> roleDefinitions = m.readValue(
                ResourceUtils.getFile(roleBaseFilePath),
                new TypeReference<List<RoleDefinition>>() {}
        );

        File entityGroupDir = ResourceUtils.getFile(groupDefinitionDir);
        if (!entityGroupDir.isDirectory()) {
            throw new Exception("Expected directory");
        }


        for (String entityType: definitionsManager.getAllKnownDefinitions()) {
            for (RoleDefinition roleDefinition: roleDefinitions) {
                String roleName = getRealmRoleWithPrefix(entityType, roleDefinition.getName());
                createRealmRole(roleName, roleDefinition.getDescription());
            }
            Optional<File> entityGroupDefinitionsFile = Arrays.stream(Objects.requireNonNull(entityGroupDir.listFiles()))
                    .filter(f -> f.getName().startsWith(entityType))
                    .findFirst();

            if (entityGroupDefinitionsFile.isPresent()) {
                List<GroupDefinition> groupDefinitions = m.readValue(
                        entityGroupDefinitionsFile.get(),
                        new TypeReference<List<GroupDefinition>>() {}
                );

                for (GroupDefinition groupDefinition: groupDefinitions) {
                    createGroup(
                            groupDefinition.getName(),
                            groupDefinition.getRealmRoles()
                                    .stream()
                                    .map(r -> getRealmRoleWithPrefix(entityType, r))
                                    .collect(Collectors.toList())
                    );
                }
            }
        }
    }

    private Keycloak buildKeycloak() {
        return KeycloakBuilder.builder()
                .serverUrl(authURL)
                .realm(realm)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .clientId(adminClientId)
                .clientSecret(adminClientSecret)
                .build();
    }

    public String createUser(String userName, String entityName) throws DuplicateRecordException, EntityCreationException {
        logger.info("Creating user with mobile_number : " + userName);
        UserRepresentation newUser = new UserRepresentation();
        newUser.setEnabled(true);
        newUser.setUsername(userName);
        CredentialRepresentation credentialRepresentation = new CredentialRepresentation();
        credentialRepresentation.setValue("password");
        credentialRepresentation.setType("password");
        newUser.setCredentials(Collections.singletonList(credentialRepresentation));
        newUser.singleAttribute("mobile_number", userName);
        newUser.singleAttribute("entity", entityName);
        UsersResource usersResource = keycloak.realm(realm).users();
        Response response = usersResource.create(newUser);
        if (response.getStatus() == 201) {
            logger.info("Response |  Status: {} | Status Info: {}", response.getStatus(), response.getStatusInfo());
            logger.info("User ID path" + response.getLocation().getPath());
            String userID = getCreatedId(response);
            logger.info("User ID : " + userID);
            return userID;
        } else if (response.getStatus() == 409) {
            logger.info("UserID: {} exists", userName);
            Optional<UserResource> userRepresentationOptional = getUserByUsername(userName);
            if (userRepresentationOptional.isPresent()) {
                UserResource userResource = userRepresentationOptional.get();
                UserRepresentation userRepresentation = userResource.toRepresentation();
                List<String> entities = userRepresentation.getAttributes().get("entity");
                if (entities.contains(entityName)) {
                    throw new EntityCreationException("Username already invited / registered for " + entityName);
                } else {
                    entities.add(entityName);
                    userResource.update(userRepresentation);
                    return userRepresentation.getId();
                }
            } else {
                logger.error("Failed fetching user by username: {}", userName);
                throw new EntityCreationException("Creating user failed");
            }
        } else {
            throw new EntityCreationException("Username already invited / registered");
        }
    }

    private Optional<UserResource> getUserByUsername(String username) {
        List<UserRepresentation> users = keycloak.realm(realm).users().search(username);
        if (users.size() > 0) {
            return Optional.of(keycloak.realm(realm).users().get(users.get(0).getId()));
        }
        return Optional.empty();
    }

    private void addUserToGroup(String groupName, UserRepresentation user) {
        keycloak.realm(realm).groups().groups().stream()
                .filter(g -> g.getName().equals(groupName)).findFirst()
                .ifPresent(g -> keycloak.realm(realm).users().get(user.getId()).joinGroup(g.getId()));
    }

    private void createGroup(String groupName, List<String> realmRoles) throws EntityCreationException {
        GroupRepresentation groupRepresentation = new GroupRepresentation();
        groupRepresentation.setName(groupName);
        Response response = keycloak.realm(realm).groups().add(groupRepresentation);
        if (!Arrays.asList(201, 409).contains(response.getStatus())) {
            throw new EntityCreationException("Error creating group");
        }

        List<RoleRepresentation> roles = keycloak.realm(realm).roles().list().stream()
                .filter(rp -> realmRoles.contains(rp.getName()))
                .collect(Collectors.toList());

        if (response.getStatus() == 201) {
            String groupId = getCreatedId(response);
            keycloak.realm(realm).groups().group(groupId)
                    .roles().realmLevel().add(roles);
        }
    }

    private void createRealmRole(String name, String description) {
        RoleRepresentation roleRepresentation = new RoleRepresentation();
        roleRepresentation.setName(name);
        roleRepresentation.setDescription(description);
        RolesResource rolesResource = keycloak.realm(realm).roles();
        try {
            rolesResource.create(roleRepresentation);
        } catch (ClientErrorException e) {
            if (e.getResponse().getStatus() != 409) {
                throw e;
            }
        }
    }

    private String getCreatedId(Response response) {
        return response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
    }

    private String getRealmRoleWithPrefix(String entityType, String baseRole) {
        return entityType.toLowerCase() + "-" + baseRole;
    }
}
