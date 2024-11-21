import {cookies} from "next/headers";
import {gql} from "@apollo/client";
import {runQuery, runQueryWithAccessToken} from "@/utils/graphql-utils";

const WHITELISTED_ENTITIES = [
    1623, // Sri Lanka
    459, // Benin
    1593, // Bolivia,
    1606, // Brazil,
    1551, // Colombia,
    577, // Costa Rica,
    1609, // Egypt
    1585, // India,
    1544, // Portugal,
    1560, // Romania,
    1559 // Tunisia
]

export async function isPersonIdPresent(): Promise<boolean> {
    const personId = (await cookies()).get("person_id");
    return !!(personId && personId.value && personId.value !== "" && personId.value !== null);
}

export async function getPersonId(accessToken?: string): Promise<number> {
    const personId = (await cookies()).get("person_id");
    if (personId && personId.value && personId.value !== "" && personId.value !== null) {
        return parseInt(personId.value);
    }

    const query = gql`
        {
            currentPerson {
                id
            }
        }
    `

    let queryResponse;
    if (accessToken) {
        queryResponse = await runQueryWithAccessToken(accessToken!, query);
    } else {
        queryResponse = await runQuery(query);
    }

    return queryResponse.currentPerson.id;
}

export async function isAiEbMember(): Promise<boolean> {
    const query = gql`
        {
            currentPerson {
                is_ai_eb_member
            }
        }
    `

    const queryResponse = await runQuery(query);
    return queryResponse.currentPerson.is_ai_eb_member;
}

export async function forceGetPersonId(accessToken?: string): Promise<number> {
    const query = gql`
        {
            currentPerson {
                id
            }
        }
    `

    let queryResponse;
    if (accessToken) {
        queryResponse = await runQueryWithAccessToken(accessToken!, query);
    } else {
        queryResponse = await runQuery(query);
    }

    return queryResponse.currentPerson.id;
}

export async function isAiesecer(): Promise<boolean> {
    const query = gql`
        {
            person(id: "${await getPersonId()}") {
                is_aiesecer
            }
        }
    `

    try {
        const queryResponse = await runQuery(query);
        return queryResponse.person.is_aiesecer;
    } catch (e) {
        console.error(e);
        return false;
    }
}

export async function getAccessibleEntities(): Promise<number[]> {
    const officeIds = [];

    const query = gql`
        {
            currentPerson {
                current_offices {
                    id
                    suboffices {
                        id
                        suboffices {
                            id
                            suboffices {
                                id
                            }
                        }
                    }
                }
            }
        }
    `

    const queryResponse = await runQuery(query);
    for (const office of queryResponse.currentPerson.current_offices) {
        officeIds.push(parseInt(office.id));
        for (const suboffice of office.suboffices) {
            officeIds.push(parseInt(suboffice.id));
            for (const subsuboffice of suboffice.suboffices) {
                officeIds.push(parseInt(subsuboffice.id));
                for (const subsubsuboffice of subsuboffice.suboffices) {
                    officeIds.push(parseInt(subsubsuboffice.id));
                }
            }
        }
    }

    return [... new Set(officeIds)];
}

export async function getAccessibleEntitiesWithNames(): Promise<{id: number, name: string}[]> {
    const officeIds = [];

    const query = gql`
        {
    currentPerson {
        current_offices {
            id
            name
            tag
            parent {
                id
                tag
            }
            suboffices {
                id
                name
                tag
                parent {
                    id
                    tag
                }
                suboffices {
                    id
                    name
                    tag
                    parent {
                        id
                        tag
                    }
                    suboffices {
                        id
                        name
                        tag
                        parent {
                            id
                            tag
                        }
                    }
                }
            }
        }
    }
}
    `

    const queryResponse = await runQuery(query);
    console.log(queryResponse.currentPerson.current_offices);

    for (const office of queryResponse.currentPerson.current_offices) {
        if (office.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(office.id))) continue;
        if (office.parent && office.parent.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(office.parent.id))) continue;
        officeIds.push({id: parseInt(office.id), name: office.name});

        for (const suboffice of office.suboffices) {
            if (suboffice.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(suboffice.id))) continue;
            if (suboffice.parent && suboffice.parent.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(suboffice.parent.id))) continue;
            officeIds.push({id: parseInt(suboffice.id), name: suboffice.name});

            for (const subsuboffice of suboffice.suboffices) {
                if (subsuboffice.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(subsuboffice.id))) continue;
                if (subsuboffice.parent && subsuboffice.parent.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(subsuboffice.parent.id))) continue;
                officeIds.push({id: parseInt(subsuboffice.id), name: subsuboffice.name});

                for (const subsubsuboffice of subsuboffice.suboffices) {
                    if (subsubsuboffice.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(subsubsuboffice.id))) continue;
                    if (subsubsuboffice.parent && subsubsuboffice.parent.tag == "MC" && !WHITELISTED_ENTITIES.includes(parseInt(subsubsuboffice.parent.id))) continue;
                    officeIds.push({id: parseInt(subsubsuboffice.id), name: subsubsuboffice.name});
                }
            }
        }
    }

    //remove duplicate office IDs
    return officeIds.filter((office, index, self) =>
        index === self.findIndex((t) => (
            t.id === office.id
        ))
    );
}